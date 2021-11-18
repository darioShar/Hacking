#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include "tcp.h"

// Do not forget to free address after use.
int open_tcp_socket(char* host, char* port, struct addrinfo** address) {
    // Determining host
    // We want to send with UDP, IPv4 or IPv6
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    int err = getaddrinfo(host, port, &hints, address);

    if (err) {
        fprintf(stderr, "Could not get address. Error %d : %s\n", err, strerror(errno));
        // just return non zero for error
        return -1;
    }

    // Now we have information in addresses.
    // Trying to create socket. Looping through addresses
    struct addrinfo* addr = *address;
    int mysocket;

    while(addr) {
        mysocket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (mysocket == -1)
            addr = addr->ai_next;
        else
            break;
    }

    if (mysocket == -1) {
        fprintf(stderr, "Could not open socket : %s\n", strerror(errno));
        return -1; // just return non zero for error
    }

    // Now providing address with right information. Don't forget to free address later.
    struct addrinfo tmp;
    memcpy(&tmp, addr, sizeof(struct addrinfo));
    freeaddrinfo(*address);
    *address = malloc(sizeof(struct addrinfo));
    memcpy(*address, &tmp, sizeof(struct addrinfo));
    
    return mysocket;
}


int read_tcp(int socketfd, void *buf, int max_size) {
    int len = 0;
    int total_data = 0;
    //buf = malloc(CHUNK_SIZE);
    //int buffer_size = CHUNK_SIZE;
    do {
        //if (buffer_size < total_data + CHUNK_SIZE) {
        //    buf = realloc(buf, buffer_size + CHUNK_SIZE);
        //    buffer_size += CHUNK_SIZE;
        //}
        len = recv(socketfd, buf + total_data, max_size - total_data, 0);
        printf("received, %d\n", len);
        total_data += len;
    }
    while(len > 0 && total_data <= max_size);
    return total_data;
}