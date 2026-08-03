#include <iomanip>
#include <cstring>
#include <iostream>
#include <string>

#include <pcap/pcap.h>

#include "util/putout.h"


std::string tcp_pcap_file;

int put_FlowKey(pcap_t* pt) {
    FlowKey* key = new FlowKey{};
    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    bool next_ex = true;
    int ex = 0;
    int count = 0;
    while (next_ex) {
        ex = pcap_next_ex(pt, &header, &data);
        switch (ex) {
            case 1:
                //14 是“Ethernet 头结束位置”，34 是“Ethernet + IPv4 最小头结束位置”
                if (header->caplen < 34) {
                    break;
                }
                std::cout << "put_packet_len: " << header->caplen << std::endl;

                // 1、判断v4 / v6
                if ((data[12] << 8 | data[13]) == 0x0800) {
                    std::cout << "ipv4" << std::endl;

                    // tcp / udp
                    if ( data[23] == 6) {
                        std::cout << "tcp" << std::endl;
                        put_mac(header, data);
                        tcp_flow_key(header, data, key);
                        count++;
                    }
                    else if (data[23] == 17) {
                        std::cout << "udp" << std::endl;
                    } else {
                        return 0;
                    }

                }
                else if ((data[12] << 8 | data[13]) == 0x86dd) {
                    std::cout << "ipv6" << std::endl;
                }


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
    delete key;
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

    put_FlowKey(pt);

    return 0;
}
