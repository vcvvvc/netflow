#include <iomanip>
#include <cstring>
#include <iostream>
#include <string>

#include <pcap/pcap.h>

#include "util/putout.h"

struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
};

std::string tcp_pcap_file;

int FlowKey_TCP(pcap_t* pt) {
    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    bool next_ex = true;
    int ex = 0;
    int count = 0;
    while (next_ex) {
        ex = pcap_next_ex(pt, &header, &data);
        switch (ex) {
            case 1:
                put_mac(header, data);
                put_packet_len(header);
                put_flow_key(header, data);

                count++;
                break;
            case -2:
                std::cout << "包数量: " << count << std::endl;
                pcap_close(pt);
                next_ex = false;
                break;
            case -1: {
                char* ss = pcap_geterr(pt);
                std::cerr << "pcap_next_ex failed: " << ss << std::endl;
                pcap_close(pt);
                next_ex = false;
                break;
            }
            default:
                break;
        }

    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 3 || std::strcmp(argv[1], "--read") != 0) {
        std::cout << "usage: " << argv[0] << " --read <pcap>" << std::endl;
        return -1;
    }
    tcp_pcap_file = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t* pt = pcap_open_offline(tcp_pcap_file.c_str(), errbuf);
    if (pt == nullptr) {
        std::cout << "pcap_open_offline() failed: " << errbuf << std::endl;
        return 1;
    }

    int type = pcap_datalink(pt);
    if (type != 1) {
        pcap_close(pt);
        std::cerr << "pcap_datalink() failed: type != 1, type = " << type << std::endl;
        return -1;
    }

    FlowKey_TCP(pt);

    return 0;
}
