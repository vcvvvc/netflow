# netflow Demo 执行计划

## 1. Demo 目标

netflow 是一个离线 pcap 流分析器：读取固定抓包文件，逐包解析普通 Ethernet II / IPv4 TCP、UDP 报文，提取五元组，按流统计并输出可读摘要。

```text
netflow --read sample.pcap
        ↓
读取 pcap → 解析单包 → ParseResult → 流聚合 → 文本摘要
```

Demo 完成标准：

- 一条命令可以读取固定 pcap；
- TCP、UDP 正常包可以得到完整五元组；
- IPv6、非 TCP/UDP、IPv4 非首片可以明确跳过；
- 截断包、非法头可以明确报告错误原因；
- 相同方向、相同五元组可以统计包数；
- 构建、测试和输出结果可重复。

## 2. 明确边界

本阶段只做离线单线程分析，不做：

- 实时网卡抓包；
- 捕获线程、解析线程和队列；
- IPv6 流解析；
- 流超时、驱逐和持久化；
- 数据库、GUI、Docker、CI 和复杂指标。

工程目标使用 C++11 兼容写法。`std::optional`、`std::unique_ptr` 等不是当前必要依赖；解析结果使用栈对象和按值返回。

## 3. 最终架构

```text
main.cpp
  ├─ 打开 pcap
  ├─ pcap_next_ex 读取一个报文
  ├─ 调用 PacketParser::parse(header, data)
  │       ↓
  │   ParseResult
  │       ├─ status
  │       ├─ flow_key
  │       └─ reason
  ├─ success → 交给 FlowAggregator
  ├─ skipped → 记录并跳过
  └─ error   → 输出 reason
```

### `main.cpp`

只负责：

- 命令行参数；
- pcap 打开、逐包读取和关闭；
- 调用 `PacketParser`；
- 根据 `ParseResult` 分流；
- 把成功结果交给后续聚合器。

不负责读取协议字段，不负责构造五元组。

### `PacketParser`

只解析一个报文：

```cpp
ParseResult parse(
    const pcap_pkthdr* header,
    const u_char* data
) const;
```

它不接收 `pcap_t*`，不读取文件，不做聚合，不直接打印最终结果。

解析过程负责两件不可分割的事情：

1. 判断当前报文的解析状态；
2. 在成功时提取 `FlowKey`。

不额外建立一个重复读取报文的 `get_status()` 流程。

### `ParseResult`

它是数据结构，不是解析器：

```cpp
struct ParseResult {
    ParseStatus status;
    FlowKey flow_key;
    std::string reason;
};
```

`ParseStatus` 使用 `enum class`：

```text
success：flow_key 有效
skipped：报文合法，但当前范围主动忽略
error：报文非法或不完整，reason 有效
```

约束：

- 只有 `status == success` 时读取 `flow_key`；
- `skipped` 和 `error` 必须提供 `reason`；
- 解析函数按值返回 `ParseResult`；
- 不使用 `new ParseResult`，不手写析构函数；
- 解析函数不直接写 `std::cout`，由 `main` 或报告层决定输出。

### `FlowKey`

保存：

- 源 IP；
- 目的 IP；
- 源端口；
- 目的端口；
- 协议号。

## 4. 当前真实基线

- `main.cpp` 仍保留旧的 pcap 读取和调试解析路径；
- `putout.h` 中的 TCP/UDP 函数仍通过 `FlowKey*` 修改外部对象并直接打印；
- `src/ParseResult.h` 当前还是未完成的类草稿，解析职责和结果职责尚未分离；
- `src/ParseResult.cpp` 当前没有正确实现 `ParseResult::parse`；
- `CMakeLists.txt` 当前只编译 `main.cpp`，尚未接入新的解析实现；
- 最新代码当前在链接阶段失败，尚未达到可运行状态；
- 旧版普通 IPv4 TCP/UDP、非首片和非 TCP/UDP 行为曾经验证通过，但重构后需要重新验证。

当前核心问题不是析构函数，而是职责和调用链尚未接通：

```text
旧代码：main → pcap 循环 → putout.h 中直接解析和打印
目标：  main → PacketParser::parse(单包) → ParseResult
```

## 5. 开发切片

每个切片只完成一个可验收目标；完成后停止并重新确认下一步。

### Slice 1：建立 `PacketParser` 到 `ParseResult` 的 TCP 单包链路

只处理 TCP：

- 将 `ParseResult` 改成 C++11 普通 `struct`；
- 去掉 `ParseResult` 的解析成员函数、构造/析构占位；
- 建立 `PacketParser::parse(header, data)` 的单包入口；
- TCP 正常报文返回 `success + FlowKey`；
- IHL 非法或端口截断返回 `error + reason`；
- `main` 根据结果继续或输出错误；
- 暂不改 UDP、聚合和最终输出格式。

验收：

- C++11 语法检查通过；
- CMake 构建成功；
- TCP 正常样例的五元组可由调用方读取；
- 截断 TCP 不会修改或留下旧的 `FlowKey`；
- 现有 CTest 继续通过。

### Slice 2：接入 UDP 单包解析

- 复用 Slice 1 的 `PacketParser` 和 `ParseResult` 契约；
- UDP 正常报文返回协议号 `17`；
- UDP 头截断返回 `error`；
- 不再依赖 UDP 函数内部打印作为正确性证明。

验收：

- UDP 正常样例的五元组可由调用方读取；
- 截断 UDP 返回明确错误；
- TCP 行为不回归。

### Slice 3：补齐单包分类

- 将 Ethernet、IPv4、IHL、分片和协议分流统一放入 `PacketParser`；
- IPv6、非 TCP/UDP、IPv4 非首片返回 `skipped`；
- 截断 Ethernet/IPv4/传输层头返回 `error`；
- `main.cpp` 只保留 pcap 生命周期和结果分流。

验收：

- 单包入口对所有当前范围输入返回明确状态；
- `main.cpp` 不再直接读取协议字段；
- 每个报文只被解析一次。

### Slice 4：加入最小 `FlowAggregator`

- 使用 `unordered_map<FlowKey, FlowSummary>`；
- 只聚合 `success`；
- 第一版只统计包数；
- 方向先区分，不自动合并反向流；
- 为 `FlowKey` 增加相等比较和哈希。

验收：

- 相同方向、相同五元组只形成一条记录；
- 包数与输入样例一致；
- `skipped/error` 不进入流表。

### Slice 5：输出 Demo 流摘要

- 输出总包数、成功数、跳过数、错误数；
- 输出每条流的五元组和包数；
- 输出错误原因；
- 清理不再需要的 MAC、IP、端口调试打印。

验收：

- 一条命令可以看到完整流摘要；
- TCP、UDP 样例都有可解释结果；
- 固定 pcap 可重复得到相同输出。

### Slice 6：补齐最小回归验证

- 正常 TCP；
- 正常 UDP；
- 截断 Ethernet/IPv4/TCP/UDP；
- IPv6；
- 非 TCP/UDP；
- IPv4 非首片。

验收：

- 构建和 CTest 通过；
- 每类输入的状态和原因稳定；
- README 写明构建、测试和当前限制。

## 6. 当前唯一下一步

只执行 **Slice 1：建立 `PacketParser` 到 `ParseResult` 的 TCP 单包链路**。

在 Slice 1 完成前：

- 不改 UDP；
- 不创建 `FlowAggregator`；
- 不加入实时抓包、线程或队列；
- 不扩展最终输出；
- 不提交或推送代码。

## 7. 停止条件

每个切片完成后必须报告：

1. 本轮改变了什么；
2. 使用了什么验证；
3. 验证是否通过；
4. 还有哪些范围未完成；
5. 下一切片准备做什么，然后停止等待明确继续。
