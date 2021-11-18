/*
 * rawip_example.c
 *
 *  Created on: May 4, 2016
 *      Author: jiaziyi
 */


#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "header.h"

#define SRC_IP  "192.168.1.111" //set your source ip here. It can be a fake one
//#define SRC_IP  "127.0.0.1"
#define SRC_PORT 48167 //set the source port here. It can be a fake one

//#define DEST_IP "129.104.89.108" //set your destination ip here
#define DEST_IP "127.0.0.1"
#define DEST_PORT 8080 //set the destination port here
#define TEST_STRING "test data" //a test string as packet payload



// Do not forget to free address after use.
int get_address(char* host, char* port, struct addrinfo** address) {
    // Determining host
    // We want to send with UDP, IPv4 or IPv6
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;

    int err = getaddrinfo(host, port, &hints, address);

    if (err) {
        fprintf(stderr, "Could not get address. Error %d : %s\n", err, strerror(errno));
        return 0;
    }

    return 1;
}




int main(int argc, char *argv[])
{
	char source_ip[] = SRC_IP;
	char dest_ip[] = DEST_IP;


	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

	char packet[65536], *data;
	char data_string[] = TEST_STRING;
	memset(packet, 0, 65536);

	//IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//UDP header pointer
	struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_udp_header psh; //pseudo header

	//data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

	//fill the data section
	strncpy(data, data_string, strlen(data_string));

	//fill the IP header here

	iph->tos = 0;
	iph->tot_len = 38;
	iph->id = 0;
	iph->frag_off = 0;
	iph->version = 4;
	iph->ihl = 5;
	iph->ttl = ~0;
	iph->protocol = 17;
	iph->check = htons(checksum(iph, 9));
	inet_pton(AF_INET, source_ip, &iph->saddr);
	inet_pton(AF_INET, dest_ip, &iph->daddr);

	//fill the UDP header
	udph->source = htons(SRC_PORT);
	udph->dest = htons(DEST_PORT);
	udph->len = htons(sizeof(struct udphdr) + sizeof(TEST_STRING));

	// fill pseudo header
	inet_pton(AF_INET, source_ip, &psh.source_address);
	inet_pton(AF_INET, dest_ip, &psh.dest_address);
	psh.placeholder = 0;
	psh.protocol = 17;
	psh.udp_length = udph->len;

	// set data for checksum of udp packet
	int virtual_udp_packet_size = sizeof(struct udphdr) + sizeof(struct pseudo_udp_header) + sizeof(TEST_STRING);
	char header_data[virtual_udp_packet_size];
	memcpy(header_data, &psh, sizeof(struct pseudo_udp_header));
	memcpy(header_data + sizeof(struct pseudo_udp_header), udph, sizeof(struct udphdr));
	memcpy(header_data + sizeof(struct pseudo_udp_header) + sizeof(struct udphdr), data, sizeof(TEST_STRING));
	udph->check = (checksum(&header_data, virtual_udp_packet_size));

	//send the packet
	struct addrinfo* addr;
	char port[10];
	sprintf(port, "%d", DEST_PORT);
	if(!get_address(dest_ip, port, &addr)){
		fprintf(stderr, "Could not construct ip address.\n");
        return 1;
	}

	if(sendto(fd, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(TEST_STRING),
			 0, addr->ai_addr, addr->ai_addrlen) == -1) {
		fprintf(stderr, "Could not send data : %s\n", strerror(errno));
        return 1;
	}

	for(int i = 0; i < sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(TEST_STRING); i++) {
		printf("%x ", packet[i]);
		if (i % 8 == 7) printf("\n");
	}
	printf("\n");

	return 0;

}
