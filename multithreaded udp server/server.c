#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include "udp.h"
#include "queue.h"

#define MAX_RECV_SIZE 65536

int mysocket;
pthread_mutex_t lock_queue = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t lastStateChange = PTHREAD_COND_INITIALIZER;

typedef struct thread_arg{
    node* n;
    int total_data;
    struct sockaddr from;
} thread_arg;


void* manage_client(void* arg) {
    thread_arg* args = (thread_arg*)arg;
    // echoing
    if (sendto(mysocket, args->n->buf, args->total_data, 0, &args->from, sizeof(args->from)) == -1) {
        fprintf(stderr, "Could not send data : %s\n", strerror(errno));
    }

    // simulate processing
    usleep(50000);

    pthread_mutex_lock(&lock_queue);
    if(enqueue_buffer(args->n)) fprintf(stderr, "Error on enqueuing node\n");
    else pthread_cond_signal(&lastStateChange);
    pthread_mutex_unlock(&lock_queue);

    free(arg);
    return NULL;
}

int main(int argc, char** argv) {

    if (argc != 3) {
        printf("Error : 2 arguments needed (port, number of threads)\n");
        return 1;
    }

    int max_threads = atoi(argv[2]);

    struct addrinfo* address;
    mysocket = open_udp_socket("localhost", argv[1], &address);

    // Now bind socket
    if (bind(mysocket, address->ai_addr, address->ai_addrlen)) {
        fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
	    return -1;
    }

    // Create queue
    create_queue_buffer(max_threads, MAX_RECV_SIZE);

    // Starting main loop
    printf("Supporting at most %d concurrent connections...\n", max_threads);

    struct sockaddr from;
    unsigned int fromlen = sizeof(struct sockaddr);

    while(1) {
        // Lock mutex to use queue
        pthread_mutex_lock(&lock_queue);
        node* n = dequeue_buffer();
        while (n == NULL) {
            pthread_cond_wait(&lastStateChange, &lock_queue);
            n = dequeue_buffer();
        }
        pthread_cond_signal(&lastStateChange);
        pthread_mutex_unlock(&lock_queue);

        printf("Total concurent connections : %d\n", queue_max_size - queue_actual_size - 1);
        // wait for data to be received
        int total_data = recvfrom(mysocket, n->buf, MAX_RECV_SIZE, 0, &from, &fromlen);
        //printf("Received data from %s (%d bytes) : \n", inet_ntoa(((struct sockaddr_in *)&from)->sin_addr), total_data);
        ((char*)n->buf)[MAX_RECV_SIZE - 1] = '\0';
        
        // Filling args
        thread_arg args = {n, total_data, from};
        thread_arg* a = malloc(sizeof(thread_arg));
        memcpy(a, &args, sizeof(thread_arg));

        // launching thread
        pthread_t thread;
        if(pthread_create(&thread, NULL, manage_client, a)) {
            fprintf(stderr, "Error creating thread\n");
            return 1;
        }
    }

    return 0;
}
