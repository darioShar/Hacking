/*
 * dns_server.c
 *
 *  Created on: Apr 26, 2016
 *      Author: jiaziyi
 */


#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdbool.h>
#include<time.h>

#include "dns.h"

const char dns_ip_answer[] = "129.104.221.104";//"157.240.21.35";

void send_simple_dns_answer(int sockfd, dns_header* dnsh, query* q, const char* ip_addr, struct sockaddr* client, int len);

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr server;

	int port = 53; //the default port of DNS service


	//to keep the information received.
	res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE];
	query queries[ANS_SIZE];


	if(argc == 2)
	{
		port = atoi(argv[1]); //if we need to define the DNS to a specific port
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	int enable = 1;

	if(sockfd <0 )
	{
		perror("socket creation error");
		exit_with_error("Socket creation failed");
	}

	//in some operating systems, you probably need to set the REUSEADDR
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
	    perror("setsockopt(SO_REUSEADDR) failed");
	}

	//for v4 address
	struct sockaddr_in *server_v4 = (struct sockaddr_in*)(&server);
	server_v4->sin_family = AF_INET;
	server_v4->sin_addr.s_addr = htonl(INADDR_ANY);
	server_v4->sin_port = htons(port);

	//bind the socket
	if(bind(sockfd, &server, sizeof(*server_v4))<0){
		perror("Binding error");
		exit_with_error("Socket binding failed");
	}

	printf("The dns_server is now listening on port %d ... \n", port);
	//print out
	uint8_t buf[BUF_SIZE]; //receiving buffer and sending buffer
	struct sockaddr remote;
	socklen_t addr_len = sizeof(remote);

	while(1)
	{
		//an infinite loop that keeps receiving DNS queries and send back a reply
		//complete your code here

		// receiving
		if(recvfrom(sockfd, (char*)buf, BUF_SIZE, 0, &remote, &addr_len) < 0 )
		{
			perror("Failed to listen for reception\n");
			exit(1);
		}
		printf("DNS message from %s received\n", inet_ntoa(((struct sockaddr_in*)&remote)->sin_addr));

		// parsing query and printing
		parse_dns_query(buf, queries, answers, auth, addit);

		send_simple_dns_answer(sockfd, buf, queries, dns_ip_answer, &remote, addr_len);

	}
}



void send_simple_dns_answer(int sockfd, dns_header* dnsh, query* q, const char* ip_addr, struct sockaddr* client, int len)
{
	//BEGIN_SOLUTION
	uint8_t send_buf[BUF_SIZE];
	int buf_pos = 0;

	//begin building the header
	memcpy(send_buf, dnsh, sizeof(dns_header));
	dns_header *dns = (dns_header*)send_buf;
	dns->qr = 1;
	dns->an_count = htons(1);

	buf_pos += sizeof(dns_header);

	// query part. copy name, then set A, IN
	uint8_t* query = send_buf + buf_pos;
	int length_name;
	build_name_section(query, q->qname, &length_name);
	query += length_name;
	((question*)query)->qtype = htons(TYPE_A);
	((question*)query)->qclass = htons(CLASS_IN);

	buf_pos += length_name + sizeof(question);

	// Now building answer part. Same start for the beginning
	// name
	uint8_t* answer = send_buf + buf_pos;
	build_name_section(answer, q->qname, &length_name);
	answer += length_name;
	// type and class
	r_element* answer_element = answer;
	answer_element->type = htons(TYPE_A);
	answer_element->_class = htons(CLASS_IN);
	answer_element->ttl = htonl(86400); // a day yay
	answer_element->rdlength = htons(4);
	
	buf_pos += length_name + 10; // attention ! seulement 10 octets pour sizeof(r_element)

	// and now copy ip
	uint32_t* ip_data = send_buf + buf_pos;
	inet_pton(AF_INET, ip_addr, ip_data);

	buf_pos += sizeof(uint32_t);

	// send dns response
	if(sendto(sockfd, (char*)send_buf, buf_pos,
			0, client, len) < 0)
	{
		perror("DNS response sending failed. ");
	}
	//END_SOLUTION
}