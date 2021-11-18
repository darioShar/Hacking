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
#include <pthread.h>
#include "udp.h"

#define MAX_MSG_SIZE 256

struct addrinfo* address;
// To send data
char str[MAX_MSG_SIZE];
int mysocket;

void* send_data() {
	if (sendto(mysocket, str, strlen(str) + 1, 0, address->ai_addr, address->ai_addrlen) == -1) {
            fprintf(stderr, "Could not send data : %s\n", strerror(errno));
        }
	return NULL;
}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        printf("Error : 3 arguments are needed (host, port, concurrent connections)\n");
        return 1;
    }

    mysocket = open_udp_socket(argv[1], argv[2], &address);
	// threads
    int num_threads = atoi(argv[3]);
	pthread_t threads[num_threads];
    while(fgets(str, MAX_MSG_SIZE, stdin) != NULL) {
        for (int i = 0 ; i < num_threads; i++) {
            if(pthread_create(threads + i, NULL, send_data, NULL)) {
                fprintf(stderr, "Error creating thread\n");
                return 1;
            }
        }
    }

    free(address);
    
    return 0;
}