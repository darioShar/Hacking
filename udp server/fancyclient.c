#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "udp.h"

#define MAX_MSG_SIZE 1024
#define MAX_RECV_SIZE 1024

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Error : 2 arguments are needed (server, server_port)\n");
        return 1;
    }

    struct addrinfo* server_address;
    int server_socket = open_udp_socket(argv[1], argv[2], &server_address);
    
    // To send data
    char str[MAX_MSG_SIZE];

    // To receive data
    char buf[MAX_RECV_SIZE];
    struct sockaddr from;
    unsigned int fromlen = sizeof(struct sockaddr);

    // Breaks with ^D (EOF)
    while(fgets(str, MAX_MSG_SIZE, stdin) != NULL) {
        if (sendto(server_socket, str, strlen(str) + 1, 0, server_address->ai_addr, server_address->ai_addrlen) == -1) {
            fprintf(stderr, "Could not send data : %s\n", strerror(errno));
        }
        // Now listening to response. No need to create another socket.
        recvfrom(server_socket, buf, MAX_RECV_SIZE, 0, &from, &fromlen);
        buf[MAX_RECV_SIZE - 1] = '\0';
        printf("%s", buf);
    }

    //free(client_address);
    free(server_address);
    
    return 0;
}