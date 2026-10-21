#include "src/PacketParser.h"
#include "src/ParseResult.h"

/*
int put_FlowKey(pcap_t* pt) {
    auto* key = new FlowKey{};
    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    bool next_ex = true;
    int ex = 0;
    int count = 0;
    while (next_ex) {
        ex = pcap_next_ex(pt, &header, &data);
        switch (ex) {
            case 1: {
                // Ethernet 头结束位置为 14，先保证可以读取 EtherType。
                if (header->caplen < 14) {
                    break;
                }
                std::cout << "put_packet_len: " << header->caplen << std::endl;

                // 1、判断v4 / v6
                const uint16_t ether_type =
                    (static_cast<uint16_t>(data[12]) << 8)
                    | static_cast<uint16_t>(data[13]);

                if (ether_type == 0x0800) {
                    // IPv4 最小头结束位置为 34。
                    if (header->caplen < 34) {
                        break;
                    }
                    std::cout << "ipv4" << std::endl;

                    const uint16_t fragment_field = static_cast<uint16_t>(data[20]) << 8 | static_cast<uint16_t>(data[21]);
                    const uint16_t fragment_offset = fragment_field & 0x1FFF;

                    if (fragment_offset != 0) {
                        std::cout << "非首片跳过解析" << std::endl;
                        break;
                    }

                    // tcp / udp
                    if ( data[23] == 6) {
                        std::cout << "tcp" << std::endl;
                        put_mac(header, data);
                        tcp_flow_key(header, data, key);
                        count++;
                    }
                    else if (data[23] == 17) {
                        std::cout << "udp" << std::endl;
                        put_mac(header, data);
                        udp_flow_key(header, data, key);
                    } else {
                        break;
                    }

                }
                else if (ether_type == 0x86dd) {
                    std::cout << "ipv6" << std::endl;
                }


                break;
            }
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
*/

int main(int argc, char** argv) {

    if (argc != 3 || std::strcmp(argv[1], "--read") != 0) {
        std::cout << "usage: " << argv[0] << " --read <pcap>" << std::endl;
        return -1;
    }

    std::string pcap_file;
    pcap_file = argv[2];

    PacketParser parser;
    if (!parser.open_pcap_file(pcap_file)) {
        return 1;
    }

    parser.parser_ex();


    // put_FlowKey(pt);

    return 0;
}
