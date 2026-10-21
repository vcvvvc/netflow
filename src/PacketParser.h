#pragma once

#include <iostream>
#include <string>

#include <pcap/pcap.h>

#include "ParseResult.h"

class PacketParser {
public:
    PacketParser();
    ~PacketParser();

    bool open_pcap_file(const std::string& pcap_file);
    void parser_ex();

private:
    ParseResult* result = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* pt = nullptr;
};
