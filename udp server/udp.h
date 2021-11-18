#pragma once

#define CHUNK_SIZE 1024

// Do not forget to free address after use.
int open_udp_socket(char* host, char* port, struct addrinfo** address);

int read_udp(int socketfd, void *buf, struct sockaddr *from, unsigned int* fromlen);
