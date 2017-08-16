all:
	gcc v1_pcap_A04.c -o test -w -lpcap -lpthread
	gcc v2_pcap_A04.c -o test2 -w -lpcap

clean:
	rm test
	rm at.txt