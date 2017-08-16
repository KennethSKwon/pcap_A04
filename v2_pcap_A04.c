
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

u_char* _get_mymac(u_char *dev_str){
	static u_char _mymac[6];
	int _s;
    struct ifreq ifr;
    _s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev_str);
    ioctl(_s, SIOCGIFHWADDR, &ifr);
    
    for(int i=0; i<6; i++)
        _mymac[i]=((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
/*
    printf("_get_mymac : ");
    for(int i=0; i<6; i++){
        printf("[%02x]",_mymac[i]);
    } printf("\n");
*/
    return _mymac;
}

int main(int argc, int *argv[]){

	pcap_t *handle;
	u_char *packet;
	int chk_packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	static struct ether_header *_eth;
	static struct ip *_ip;
	static int _packet_pointer=0;

	char dev_str[80];
	strcpy(dev_str,argv[1]);
	static u_char ip_str1[80];
	strcpy(ip_str1,argv[2]);
	static u_char ip_str2[80];
	strcpy(ip_str2,argv[3]);

//DELETE
	u_char *_mymac;
	_mymac=_get_mymac(dev_str);





	int r=0;
	int k=0;
	u_char buff[80];
	handle = pcap_open_live(dev_str, BUFSIZ, 1, 1000, errbuf);
	while(1){
		chk_packet = pcap_next_ex(handle, &header,&packet);
		memcpy(buff,packet,80);
		_packet_pointer=0;
		if(chk_packet==0){
				printf("chk_packet=0\n");
				return -1;
		}
		else if(chk_packet==1){
			_eth=(struct ether_header*)(packet);
			_packet_pointer+=sizeof(struct ether_header);

			//printf("=====================================================\n");

// END : DATA LINK LAYER	

// START : NETWORK LAYER
			if(ntohs(_eth->ether_type)==ETHERTYPE_IP){
				_ip=(struct ip*)(&(packet[_packet_pointer])); 
				_packet_pointer+=_ip->ip_hl*4;
/*
				printf("*********************NETWORK Layer*******************\n");
				printf("\ndst IP : %s\n", inet_ntoa( _ip->ip_dst));
				printf("src IP : %s\n", inet_ntoa( _ip->ip_src));
*/				
				
				//printf("eht dhost: %s\n",_ether_ntoa((struct ether_header*) _eth->ether_dhost));
				//printf("mymac : %s\n",_mymac);
				/*
				for(int i=0; i<6;i++){
					printf("[%02x]",_eth->ether_dhost[i]);
				}printf("\n");
				for(int i=0; i<6;i++){
					printf("[%02x]",_mymac[i]);
				}
				*/
				/*
				printf("[%d]\n",k++);
				printf("\nip_str2: %s\n",ip_str2);
				printf("inet_: %s\n",inet_ntoa( _ip->ip_dst));
				if(strcmp(ip_str2,inet_ntoa( _ip->ip_dst))==0){	
					printf("*OK*\n");
				}
				*/
			
				if(_ip->ip_p==0x01)
					printf("condition 1: [%d]\n",r++);
				if(memcmp(_eth->ether_dhost,_mymac,6)){
					printf("condition 2: [%d]\n",r++);
					for(int i=0; i<6; i++)
						printf("[%02x]",_mymac[i]);
					printf("\n");
					for(int i=0; i<6; i++)
						printf("[%02x]",_eth->ether_dhost);
					
				}
				if(strcmp(ip_str2,inet_ntoa( _ip->ip_dst))==0)
					printf("condition 3: [%d]\n",r++);

				//_ip->ip_p==0x01&&
				if(memcmp(_eth->ether_dhost,_mymac,6)&&strcmp(ip_str2,inet_ntoa( _ip->ip_dst))==0){
					//printf("protocol[%02x]\n",_ip->ip_p);
					printf("&&&&&&&[%d]&&&&&&&&\n",(k++)+1);
// START : DATA LINK LAYER
/*
	printf("packet:\n");
	for(int i=0; i<80;i++){
		printf("[%02x]",packet[i]);
	} printf("\n");

	printf("\nbuff:\n");
	for(int i=0; i<80;i++){
		//buff[i]=0x00;
		printf("[%02x]",buff[i]);
	} printf("\n");
*/
	memcpy(buff,_eth->ether_shost,6);
	memcpy(buff+6,_eth->ether_dhost,6);
/*	
	printf("\nbuff_after:\n");
	for(int i=0; i<80;i++){
		//buff[i]=0x00;
		printf("[%02x]",buff[i]);
	} printf("\n");
*/
	pcap_sendpacket(handle, buff, 80);

/*

			printf("================DATA LINK Layer=======================\n");
			printf("dst MAC : %s\n", ether_ntoa((struct ether_header*) _eth->ether_dhost));
			printf("src MAC : %s\n", ether_ntoa((struct ether_header*) _eth->ether_shost));
			printf("Type    : %04x\n\n", ntohs(_eth->ether_type));



					u_char tmp_buf[80];
					struct ether_header *tmp=(struct ether_header*)tmp_buf;

					printf("1>%s\n",ether_ntoa((struct ether_header*) tmp->ether_dhost));
					printf("1>%s\n",ether_ntoa((struct ether_header*) _eth->ether_dhost));
					printf("1>%s\n",ether_ntoa((struct ether_header*) _eth->ether_shost));

					memcpy(tmp->ether_dhost,_eth->ether_dhost,6);
					memcpy(tmp->ether_dhost,_eth->ether_shost,6);
					memcpy(tmp->ether_shost,tmp->ether_dhost,6);
					//strcpy(ether_ntoa((struct ether_header*) tmp->ether_dhost),ether_ntoa((struct ether_header*) _eth->ether_dhost));
					printf("2>%s\n",ether_ntoa((struct ether_header*) tmp->ether_dhost));
					printf("2>%s\n",ether_ntoa((struct ether_header*) _eth->ether_dhost));
					printf("2>%s\n",ether_ntoa((struct ether_header*) _eth->ether_shost));
//					_eth->ether_dhost=_eth->ether_shost;
//					_eth->ether_shost=tmp->eth->ether_dhost;
*/
/*
					u_char tmp[6];
					memcpy(tmp,_eth->ether_dhost,6);
*/

					//send_packet()	
				}			
				if(memcmp(_eth->ether_dhost,_mymac,6)&&strcmp(ip_str1,inet_ntoa( _ip->ip_dst))==0){

						memcpy(buff,_eth->ether_shost,6);
						memcpy(buff+6,_eth->ether_dhost,6);

				}
			}

// END : NETWORK LAYER
		}
		else{
			printf("ck_packout wrong -1(Device down) or -2(EOF)\n");
			return -1;
		}
	}
    return 0;
}