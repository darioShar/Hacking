/*
 * pcap_example.c
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */


#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include<sys/socket.h>
#include <sys/types.h>
#include<arpa/inet.h>

#include "header.h"


#define BUF_SIZE 65536

//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);


// get the dns server address
void get_dns_server_ip(char* dns_ip) {
    FILE* file;
    char line[256];
    if ((file = fopen("/etc/resolv.conf", "r")) == NULL) {
        printf("Failed to read dns servers' list from /etc/resolv.conf\n");
        dns_ip = NULL;
        return;
    }
    while(fgets(line, 256, file)) {
        if(strncmp(line, "nameserver", 10) == 0) {
            strcpy(dns_ip, line + 11);
            dns_ip[strlen(dns_ip) - 1] = '\0';
            return;
        }
    }
    dns_ip = NULL;
}

int main(int argc, char *argv[])
{
	pcap_t *handle;

    char err_buf[PCAP_ERRBUF_SIZE];

    // problem : any isn't capturing anything on my machine.
    // Since dns server here in polytechnique is in local network, we use
    // loopback to sniff communications.
    char *dev_name = "lo";
	bpf_u_int32 net_ip, mask;


	//look up the chosen device
	int ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
	if(ret < 0)
	{
		fprintf(stderr, "Error looking up net: %s \n", dev_name);
		exit(1);
	}

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = net_ip;
	char ip_char[100];
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("NET address: %s\n", ip_char);

	addr.sin_addr.s_addr = mask;
	memset(ip_char, 0, 100);
	inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
	printf("Mask: %s\n", ip_char);

	//open the device
	//
	//	   pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
	//	   char *ebuf)
	//
	//	   snaplen - maximum size of packets to capture in bytes
	//	   promisc - set card in promiscuous mode?
	//	   to_ms   - time to wait for packets in miliseconds before read
	//	   times out
	//	   errbuf  - if something happens, place error string here
	//
	//	   Note if you change "prmisc" param to anything other than zero, you will
	//	   get all packets your device sees, whether they are intendeed for you or
	//	   not!! Be sure you know the rules of the network you are running on
	//	   before you set your card in promiscuous mode!!
    handle = pcap_open_live(dev_name, BUF_SIZE, 1, 1000, err_buf);

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

    // Now setting up rule
    struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[256];
    char dns_ip[50];
    get_dns_server_ip(dns_ip);
    const char first_expr[] = "host ";
    strcpy(filter_exp, first_expr);
    strcpy(filter_exp + strlen(first_expr), dns_ip);

    if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }

    printf("Device %s is opened. Begin sniffing with filter \"%s\" ...\n", dev_name, filter_exp);
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);

	pcap_close(handle);

	return 0;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    // DNS packet is usually sent over UDP, if its size is small enough.
    // structure of packet is : ethernet header, ip header, udp header and dns section.

    //printf("a packet is received! %d \n", total++);
    int size = header->len;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;

    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
    case 1:  //ICMP Protocol
        ++icmp;
        print_icmp_packet( buffer , size);
        break;

    case 2:  //IGMP Protocol
        ++igmp;
        break;

    case 6:  //TCP Protocol
        ++tcp;
        print_tcp_packet(buffer , size);
        break;

    case 17: //UDP Protocol
        ++udp;
        print_udp_packet(buffer , size);
        break;

    default: //Some Other Protocol like ARP etc.
        ++others;
        break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);


}

