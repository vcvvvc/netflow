#pragma once

#include <cstdint>

// What：定义一个网络报文对应的流五元组。
// Why：让五元组成为独立数据，不再归属于具体的输出函数。
struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
};

enum class ParseStatus {
    success,
    skipped,
    error
};

class ParseResult {
public:
    ParseResult();
    ~ParseResult();

private:
    ParseStatus status;
    FlowKey flow_key;
};
