#include <iostream>
#include <string>

#include <pcap/pcap.h>

const std::string tcp_pcap_file = "/Users/vw/Downloads/clean_vm_19888.pcap";

int main() {
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t* pt = pcap_open_offline(tcp_pcap_file.c_str(), errbuf);
    if (pt == nullptr) {
        std::cout << "pcap_open_offline() failed: " << errbuf << std::endl;
        return 1;
    }
    std::cout << pt << std::endl;

    pcap_close(pt);

    return 0;
}
