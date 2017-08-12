//HEADERS*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

u_char* _get_mymac(u_char *dev_str);
u_char* _get_myip(u_char *dev_str);
u_char* _ip_string_to_bytes(u_char *ip_str);
void _send_arp(u_char *dev_str,u_char *dst_mac,u_char *src_mac,u_char *target_ip,u_char *sender_ip,u_char *target_mac, u_char *sender_mac, u_short _opcode);
u_char* _detect_mac(u_char *dev_str,u_char *chk_ip);
u_char* thread_detect_mac(u_char *chk_ip);


int main(int argc, char *argv[]){
//START: error HOW TO USE
	printf("=====START========\n");
	if(argc<3){
		printf("[How to use]: ./[exec file] [NIC] [A1_target_ip] [A2_target_ip] (...[B1_target_ip] [B2_target_ip])");
		return -1;
	}
//START: argv[1] DEVICE	
	static u_char dev_str[80];
	strcpy(dev_str,argv[1]);
//START: argv[2,3...] IP
	u_char *argv_ip[argc-2];
	for(int i=0; i<argc-2; i++){
		printf("*argv %d: ",i);
		argv_ip[i]=_ip_string_to_bytes(argv[i+2]);
		
	}


	printf("==================\n");
//START: MY MAC
	u_char *_mymac;
	_mymac=_get_mymac(dev_str);
//START: MY IP
	u_char *_myip;
	_myip=_get_myip(dev_str);
//START: GET TARGET MAC with ARP reqeust
	pthread_t t_id[argc-2];
	u_char thread_param=0;
	u_char *thr_ret;


	//argv[2]'s mac = argv_ip[0]'s mac
	#define ARP_BROAD "\xff\xff\xff\xff\xff\xff"
	#define ARP_DEFAULT_TMAC "\x00\x00\x00\x00\x00\x00"
	
	u_char *argv_mac[argc-2];
	memset(argv_mac,0,sizeof(argv_mac));

	while(1){		
		pthread_create(&t_id,NULL,thread_detect_mac,argv_ip[0]);
		_send_arp(dev_str,ARP_BROAD,_mymac,argv_ip[0],_myip,ARP_DEFAULT_TMAC,_mymac,0x0001);
		pthread_join(t_id,&argv_mac[0]);	
		if(argv_mac[0]!=NULL){
			printf("NULL00\n");
			break;
		}
	}

/*
	argv_mac[0]=_detect_mac(dev_str,argv_ip[0]);
	printf("ARGV MAC[0]: ");
	for(int i=0; i<4; i++){
		printf("[%02x]", argv_mac[0][i]);
	} printf("\n");
*/

		
	


}
u_char* thread_detect_mac(u_char *chk_ip){
	u_char *get_mac;

	get_mac=_detect_mac("ens33",chk_ip);
	printf("THREAD MAC: ");
	for(int i=0; i<6; i++){
		printf("[%02x]",get_mac[i]);
	}printf("\n");	
}


u_char* _get_mymac(u_char *dev_str){
	static u_char _mymac[6];
	int _s;
    struct ifreq ifr;
    _s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev_str);
    ioctl(_s, SIOCGIFHWADDR, &ifr);
    
    for(int i=0; i<6; i++)
        _mymac[i]=((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
    
    printf("_get_mymac : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",_mymac[i]);
    } printf("\n");

    return _mymac;
}
u_char* _get_myip(u_char *dev_str){
	struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];  // defined  NI_MAXHOST==1025
    
    if (getifaddrs(&ifaddr) == -1) 
    {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL)
            continue;  

        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if((strcmp(ifa->ifa_name,dev_str)==0)&&(ifa->ifa_addr->sa_family==AF_INET))
        {
            if (s != 0)
            {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }
            //printf("\nInterface : <%s>\n",ifa->ifa_name );
            //printf("Address : <%s>\n", host); 
        }
    }

    freeifaddrs(ifaddr);
    return _ip_string_to_bytes(host);
}
u_char* _ip_string_to_bytes(u_char *ip_str){
	static u_char _ip[4];
	const char tk[2] = ".";	
	char *token;

	int i=0;
	token = strtok(ip_str, tk);
	while( token != NULL ) 
	{
	  _ip[i++]=atoi(token);
	  token = strtok(NULL, tk);
	}

	printf("IP: ");
	for(int i=0; i<4; i++){
		printf("%d",_ip[i]);
		if(i<3) printf(".");
	} printf("\n");
	
	return  _ip;
}
void _send_arp(u_char *dev_str,u_char *dst_mac,u_char *src_mac,u_char *target_ip,u_char *sender_ip,u_char *target_mac, u_char *sender_mac, u_short _opcode){
	u_char buffer[80];
    struct ether_header *_eth=(struct ether_header*)buffer;
    struct ether_arp *_arp=(struct ether_arp*)(buffer+sizeof(struct ether_header));
 
    //ETHER HEADER
    memcpy(_eth->ether_dhost, dst_mac, 6);
 	memcpy(_eth->ether_shost, src_mac, 6);
 	_eth->ether_type=htons(ETHERTYPE_ARP);//htons(ETHERTYPE_ARP);
 	// ARP HEADER
    _arp->arp_hrd=htons(0x0001);//htons(0x0001)
    _arp->arp_pro=htons(0x0800);//htons(0x0008)
    _arp->arp_hln=0x06;
    _arp->arp_pln=0x04;
    _arp->arp_op=htons(_opcode);//htons(0x0001)
    memcpy(_arp->arp_sha, sender_mac,6);
    memcpy(_arp->arp_spa, sender_ip,4);
    memcpy(_arp->arp_tha, target_mac,6);
    memcpy(_arp->arp_tpa, target_ip,4);
/*
    for(int i=0; i<sizeof(struct ether_header)+sizeof(struct ether_arp); i++){
    	if(i%16==0) printf("\n");
    	printf("[%02x]",buffer[i]);
    } printf("\n");
*/
	pcap_t *s_handle;
	u_char *s_packet;
	struct pcap_pkthdr *header;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (dev_str == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	s_handle = pcap_open_live(dev_str, BUFSIZ, 1, 1000, errbuf);
	if (s_handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev_str, errbuf); return(2); }
    pcap_sendpacket(s_handle, buffer, sizeof(struct ether_header)+sizeof(struct ether_arp));
}
u_char* _detect_mac(u_char *dev_str,u_char *chk_ip){
	pcap_t *handle;
	u_char *packet;
	int chk_packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	static u_char *get_mac;
	handle = pcap_open_live(dev_str, BUFSIZ, 1, 1000, errbuf);
	while(1){
		chk_packet = pcap_next_ex(handle, &header,&packet);
		if(chk_packet==0){
				printf("chk_packet=0\n");
				return -1;
		}
		else if(chk_packet==1){
			struct ether_header *_eth=(struct ether_header*)(packet);
			struct ether_arp *_arp=(struct ether_arp*)(packet+sizeof(struct ether_header));

			if(ntohs(_eth->ether_type)==0x0806&&ntohs(_arp->arp_op)==0x0002&&(strcmp(_arp->arp_spa,chk_ip)!=0)){
				printf("*GET ARP REPLY*\n");
					return get_mac=_arp->arp_sha;
				
			}
		}
		else{
			printf("ck_packout wrong -1(Device down) or -2(EOF)\n");
			return -1;
		}
	}
    return 0;
}