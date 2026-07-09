void put_flow_key(const pcap_pkthdr* header, const u_char* data) {

}

void put_packet_len(const pcap_pkthdr* header) {
    //  header->caplen = 实际被 pcap 文件保存下来的长度
    // header->len    = 这个包在线路上的原始长度
    std::cout << "put_packet_len: " << header->caplen << std::endl;
}

int put_mac(const pcap_pkthdr* header, const u_char* data) {
    if ( header->caplen < 12) {
        std::cout << "pcap_next_ex() failed: caplen < 12 = " << header->caplen << std::endl;
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        if (i > 0) {
            std::cout << ":";
        }
        else if (i == 0) {
            std::cout << "dest_mac: ";
        }
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;

    for (int i = 6;i < 12; i++) {
        if (i > 6) {
            std::cout << ":";
        }
        else if (i == 6) {
            std::cout << "src_mac: ";
        }
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
    return 1;
}