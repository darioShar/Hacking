#pragma once

#define CHUNK_SIZE 1024

// Do not forget to free address after use.
int open_tcp_socket(char* host, char* port, struct addrinfo** address);

int read_tcp(int socketfd, void *buf, int max_size);
