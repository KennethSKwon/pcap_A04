#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/tcp.h>


#define MAC_LEN 6

int _find_myip(char* dev_str);
int _find_mymac(char *dev_str);

int main(int argc, char *argv[])
{          
//TAKE ARGUMENT 1, 2, 3
	u_char dev_str[80];
	strcpy(dev_str,argv[1]);
	//printf("Dev: %s\n",dev_str);

	u_char sender_ip_str[80] ;
	strcpy(sender_ip_str,argv[2]);

	u_char target_ip_str[80];
	strcpy(target_ip_str,argv[3]);

//STRAT : ARGUEMENT TO IP ADDRESS
	const char tk[2] = ".";	
	char *token;
	u_char sender_ip[4];
	u_char target_ip[4];

	int i=0;
	token = strtok(sender_ip_str, tk);
	while( token != NULL ) 
	{
	  sender_ip[i++]=atoi(token);
	  token = strtok(NULL, tk);
	}

	i=0;
	token = strtok(target_ip_str, tk);
	while( token != NULL ) 
	{
	  target_ip[i++]=atoi(token);
	  token = strtok(NULL, tk);
	}


//START : GET MY MAC
	u_char _mymac[6];
    int _s;
    struct ifreq ifr;
    _s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev_str);
    ioctl(_s, SIOCGIFHWADDR, &ifr);
    
    for(int i=0; i<6; i++){
        _mymac[i]=((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
    }

    printf("local mac : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",_mymac[i]);
    }
// END : GET MY MAC

// START : GET MY IP
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
//END : GET MY IP

//START : SEND NORMAL ARP REQUEST
    u_char buffer[80];

    struct ether_header *_eth=(struct ether_header*)buffer;
    //_eth=(struct ether_header*)malloc(sizeof(struct ether_header));
    struct ether_arp *_arp=(struct ether_arp*)(buffer+sizeof(struct ether_header));
    //_arp=(struct ether_arp*)malloc(sizeof(struct ether_arp));

    //ETHER HEADER
    memcpy(_eth->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);
 	memcpy(_eth->ether_shost, _mymac, 6);
 	_eth->ether_type=htons(ETHERTYPE_ARP);//htons(ETHERTYPE_ARP);
 	// ARP HEADER
    _arp->arp_hrd=htons(0x0001);//htons(0x0001)
    _arp->arp_pro=htons(0x0800);//htons(0x0008)
    _arp->arp_hln=0x06;
    _arp->arp_pln=0x04;
    _arp->arp_op=htons(0x0001);//htons(0x0001)
    memcpy(_arp->arp_sha, _mymac,6);
    memcpy(_arp->arp_spa, sender_ip,4);
    memcpy(_arp->arp_tha, "\x00\x00\x00\x00\x00\x00",6);
    memcpy(_arp->arp_tpa, target_ip,4);

    printf("\n====================================");
    printf("\nIN ETH DMAC: ");
 	for(int i=0; i<6; i++){
 		printf("[%02x]",_eth->ether_dhost[i]); 		
 	}
 	printf("\nIN ETH SMAC: ");
	for(int i=0; i<6; i++){
 		printf("[%02x]",_eth->ether_shost[i]); 		
 	}
 	printf("\nIN ETH TYPE: %04x",_eth->ether_type);
 	
 	printf("\nIN ARP HARDWARE TYPE: %04x\n",_arp->arp_hrd);
 	printf("IN ARP PROTOCOL TYPE: %04x\n",_arp->arp_pro);
 	printf("IN ARP HARDWARE SIZE: %04x\n",_arp->arp_hln);
 	printf("IN ARP PROTOCOL SIZE: %04x\n",_arp->arp_pln);
 	printf("IN ARP OP CODE: %04x\n",_arp->arp_op);
 	printf("IN ARP SENDER MAC: ");
 	for(int i=0; i<6; i++){
 		printf("[%02x]",_arp->arp_sha[i]); 		
 	}
 	printf("\nIN ARP SENDER IP: ");
	for(int i=0; i<4; i++){
 		printf("%d",_arp->arp_spa[i]);
 		if(i<3)printf("."); 		
 	}
 	printf("\nIN ARP DMAC: ");
 	for(int i=0; i<6; i++){
 		printf("[%02x]",_arp->arp_tha[i]); 		
 	}
 	printf("\nIN ARP SENDER IP: ");
	for(int i=0; i<4; i++){
 		printf("%d",_arp->arp_tpa[i]);
 		if(i<3)printf("."); 		
 	} printf("\n");

 	if( strcmp(_eth->ether_dhost,"\xff\xff\xff\xff\xff\xff")!=0)
 		printf("NOW ARP REQUEST\n");


//START: SEND ARP REQUEST
	pcap_t *s_handle;
	u_char *s_packet;
	struct pcap_pkthdr *header;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;


	if (dev_str == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	s_handle = pcap_open_live(dev_str, BUFSIZ, 1, 1000, errbuf);
	if (s_handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev_str, errbuf); return(2); }
	
	for(int i=0; i<sizeof(struct ether_header)+sizeof(struct ether_arp);i++){
		if(i%16==0)printf("\n");
		printf("[%02x]",buffer[i]);

	}	printf("\n");
// WORK

	while(1){
		pcap_sendpacket(s_handle, buffer, sizeof(struct ether_header)+sizeof(struct ether_arp));
		sleep(1);
		printf("gone 1sec\n");
	}




    
    return 0;
}
//mymac : https://stackoverflow.com/questions/6767296/how-to-get-local-ip-and-mac-address-c
//myip : https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux


