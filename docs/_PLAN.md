# netflow 当前执行计划

## Context

当前只处理一个目标：从离线 pcap 中读取 IPv4/TCP 报文，并提取 TCP `FlowKey`。

当前调用链：

```text
main
  → PacketParser::open_pcap_file()
  → PacketParser::parser_ex()
  → PacketParser::get_tcp_flowkey(header, data)
```

架构图：

```text
┌────────┐
│  main  │  参数校验、创建 Parser、启动处理
└───┬────┘
    │
    ▼
┌──────────────────────┐
│    PacketParser      │
│  ┌────────────────┐  │
│  │    pcap_t*     │  │  文件句柄由 Parser 持有
│  └───────┬────────┘  │
│          │ pcap_next_ex(header, data)
│          ▼           │
│  Ethernet → IPv4     │
│       → 分片判断     │
│       → TCP          │
│       → FlowKey      │
└──────────────────────┘
```

已确定的边界：

- `PacketParser` 持有并释放 `pcap_t*`；
- `header`、`data` 只在当前报文处理期间有效；
- `ParseResult` 使用值成员保存 `FlowKey`；
- 当前只做离线、单线程、TCP；
- 暂不处理 UDP 五元组、流聚合和最终摘要输出。

## 当前切片：完成 TCP `FlowKey` 提取

唯一验收目标：

> 对正常 IPv4/TCP 报文，`get_tcp_flowkey(header, data)` 能得到完整的源 IP、目的 IP、源端口、目的端口和协议号；对非法或截断报文不越界、不保留旧结果。

Checklist：

- [x] `ParseResult` 改为 `struct`，删除旧的 `ParseResult.cpp`；
- [x] `PacketParser` 能打开离线 pcap，并校验 Ethernet 链路层；
- [x] `parser_ex()` 调用 `pcap_next_ex()` 读取报文；
- [x] `ex == 1` 进入报文处理，`ex == -1` 输出读取错误并结束，`ex == -2` 正常结束；
- [x] 使用 `header->caplen` 完成 Ethernet、IPv4 最小头和基础协议分类；
- [x] IPv4 非首片不进入 TCP/UDP 解析；
- [x] `main` 调用 `parser_ex()`；
- [ ] `get_tcp_flowkey(header, data)` 校验 IHL 和 TCP 头长度；
- [ ] 提取并保存 TCP 五元组；
- [ ] 正常 TCP 样例输出可核对的 `FlowKey`；
- [ ] 截断 TCP 样例验证不会越界或留下旧 `FlowKey`；
- [ ] 构建和一次真实样例运行通过。

完成当前切片后停止，先报告完成内容和验证结果，等待下一步指令。
