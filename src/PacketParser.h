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
    void get_tcp_flowkey(const pcap_pkthdr* header, const u_char* data);
    void get_udp_flowkey(const pcap_pkthdr* header, const u_char* data);

private:
    ParseResult result;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* pt = nullptr;
};
