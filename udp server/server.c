#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "udp.h"

#define MAX_RECV_SIZE 1024

int main(int argc, char** argv) {

    if (argc != 2) {
        printf("Error : 1 argument is needed (port)\n");
        return 1;
    }

    struct addrinfo* address;
    int mysocket = open_udp_socket("localhost", argv[1], &address);

    // Now bind socket
    if (bind(mysocket, address->ai_addr, address->ai_addrlen)) {
        fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
	    return -1;
    }

    // Now waiting for incoming message
    char buf[MAX_RECV_SIZE];
    struct sockaddr from;
    unsigned int fromlen = sizeof(struct sockaddr);

    while(1) {
        int total_data = recvfrom(mysocket, buf, MAX_RECV_SIZE, 0, &from, &fromlen);
        //printf("Received data from %s (%d bytes) : \n", inet_ntoa(((struct sockaddr_in *)&from)->sin_addr), total_data);
        buf[MAX_RECV_SIZE - 1] = '\0';
        printf("%s", (char*)buf);
        if (sendto(mysocket, buf, total_data, 0, &from, sizeof(from)) == -1) {
            fprintf(stderr, "Could not send data : %s\n", strerror(errno));
        }
    }

    free(address);

    return 0;
}
