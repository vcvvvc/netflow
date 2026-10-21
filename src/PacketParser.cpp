#include "PacketParser.h"

PacketParser::PacketParser() {

}

PacketParser::~PacketParser() {
    if (pt != nullptr) {
        pcap_close(pt);
    }

}

bool PacketParser::open_pcap_file(const std::string& pcap_file) {

    // 打开离线 pcap 文件，获取后续读取报文所需的句柄。
    pt = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (pt == nullptr) {
        // 打开失败时输出 libpcap 提供的具体原因，当前流程无法继续。
        std::cout << "pcap_open_offline() failed: " << errbuf << std::endl;
        return false;
    }

    // 查询抓包文件的链路层类型；当前解析逻辑只支持 Ethernet。
    int type = pcap_datalink(pt);
    if (type != 1) {
        // 当前链路层不受支持，退出前释放已经打开的 pcap 句柄。
        pcap_close(pt);
        std::cerr << "pcap_datalink() failed: type != 1, type = " << type << std::endl;
        return false;
    }

    return true;
}

void PacketParser::parser_ex() {
    pcap_pkthdr* header = nullptr;
    const u_char* data = nullptr;
    bool next_ex = true;
    int ex = 0;
    int count = 0;

    // while (next_ex) {
    //     ex = pcap_next_ex(pt, &header, &data);
    //     switch (ex) {
    //         case 1:
    //             // Ethernet 头结束位置为 14，先保证可以读取 EtherType。
    //             if (header->caplen < 14) {
    //                 break;
    //             }
    //             std::cout << "put_packet_len: " << header->caplen << std::endl;
    //
    //             // 判断v4 / v6
    //             const uint16_t ether_type =
    //                 (static_cast<uint16_t>(data[12]) << 8)
    //                 | static_cast<uint16_t>(data[13]);
    //
    //         default:
    //             break;
    //     }
    // }

}