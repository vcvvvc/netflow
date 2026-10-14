struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
};

void tcp_flow_key(const pcap_pkthdr* header, const u_char* data, FlowKey* key) {
    const uint8_t hdr_len = static_cast<uint8_t>((data[14] & 0X0F) * 4);
    if (hdr_len < 20) {
        std::cout << "invalid IPv4 header: IHL < 5" << std::endl;
        return;
    }

    const uint16_t tcp_offset = static_cast<uint16_t>(14 + hdr_len);
    if (header->caplen < tcp_offset + 4) {
        std::cout << "invalid IPv4/TCP packet: truncated ports" << std::endl;
        return;
    }
    std::cout << "hdr_len: " << std::dec << static_cast<int>(hdr_len) << std::endl;

    uint32_t a = static_cast<uint32_t>(data[26]) << 24;
    uint32_t b = static_cast<uint32_t>(data[27]) << 16;
    uint32_t c = static_cast<uint32_t>(data[28]) << 8;
    uint32_t d = static_cast<uint32_t>(data[29]);

    key->src_ip = a | b | c | d;
    std::cout << "src_ip: " << std::dec
              << ((key->src_ip >> 24) & 0xFF) << "."
              << ((key->src_ip >> 16) & 0xFF) << "."
              << ((key->src_ip >> 8) & 0xFF) << "."
              << (key->src_ip & 0xFF) << std::endl;

    key->src_port = (static_cast<uint16_t>(data[tcp_offset]) << 8)
                    | static_cast<uint16_t>(data[tcp_offset + 1]);
    std::cout << "src_port: " << key->src_port << std::endl;

    //====dst_ip
    uint32_t dsta = static_cast<uint32_t>(data[30]) << 24;
    uint32_t dstb = static_cast<uint32_t>(data[31]) << 16;
    uint32_t dstc = static_cast<uint32_t>(data[32]) << 8;
    uint32_t dstd = static_cast<uint32_t>(data[33]);

    key->dst_ip = dsta | dstb | dstc | dstd;
    std::cout << "dst_ip: " << std::dec
              << ((key->dst_ip >> 24) & 0xFF) << "."
              << ((key->dst_ip >> 16) & 0xFF) << "."
              << ((key->dst_ip >> 8) & 0xFF) << "."
              << (key->dst_ip & 0xFF) << std::endl;

    key->dst_port = (static_cast<uint16_t>(data[tcp_offset + 2]) << 8)
                    | static_cast<uint16_t>(data[tcp_offset + 3]);
    std::cout << "dst_port: " << key->dst_port << std::endl;

    key->proto = static_cast<uint8_t>(data[23]);
    std::cout << "proto: " << std::dec << (key->proto & 0XFF) << std::endl;
}


int put_mac(const pcap_pkthdr*, const u_char* data) {
    const auto print_mac = [](const char* label, const u_char* mac) {
        std::cout << label << std::hex << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            if (i > 0) {
                std::cout << ':';
            }
            std::cout << std::setw(2)
                      << static_cast<unsigned int>(mac[i]);
        }
        std::cout << '\n';
    };

    print_mac("dest_mac: ", data);
    print_mac("src_mac: ", data + 6);
    std::cout << std::dec;
    return 1;
}

void udp_flow_key(const pcap_pkthdr* header, const u_char* data, FlowKey* key) {
    const uint8_t hdr_len = static_cast<uint8_t>((data[14] & 0X0F) * 4);
    if (hdr_len < 20) {
        std::cout << "invalid IPv4 header: IHL < 5 (header length < 20 bytes)" << std::endl;
        return;
    }
    const uint16_t udp_offset = static_cast<uint16_t>(14 + hdr_len);
    if (header->caplen < udp_offset + 8) {
        std::cout << "truncated UDP header" << std::endl;
        return;
    }


    //udp->port
    key->src_port =
        (static_cast<uint16_t>(data[udp_offset]) << 8)
        | static_cast<uint16_t>(data[udp_offset + 1]);

    std::cout << "src_port: " << key->src_port << std::endl;

    key->dst_port =
        (static_cast<uint16_t>(data[udp_offset + 2]) << 8)
        | static_cast<uint16_t>(data[udp_offset + 3]);

    std::cout << "udp_prot" << key->dst_port << std::endl;
}
