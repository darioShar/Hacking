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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "tcp.h"
#include "queue.h"

#define MAX_RECV_SIZE 65536

int mysocket;
pthread_mutex_t lock_queue = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t lastStateChange = PTHREAD_COND_INITIALIZER;

typedef struct thread_arg{
    node* n;
    int socket;
} thread_arg;

const char* response = "HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Content-Length: 254\r\n\
Date: Thu, 15 Sep 2011 07:00:20 GMT\r\n\
Server: gws\r\n\
X-XSS-Protection: 1; mode=block\r\n\
\r\n\
<!DOCTYPE html>\
<html lang=\"en\">\
<head>\
<meta charset=\"utf-8\">\
<title>Facebook</title>\
</head>\
<body>\
<h1>Welcome on Facebook !</h1>\
<p>This is definitely a facebook page.</p>\
<p>Please send some password</p>\
</br>\
</br>\
<p>By Clément and Dario</p>\
</body>\
</html>";

int total_accepted_connection;

void* manage_client(void* arg) {
    thread_arg* args = (thread_arg*)arg;

    /*
    // reading
    recv(args->socket, args->n->buf, MAX_RECV_SIZE, 0);

    // echoing
    write(args->socket, args->n->buf, strlen(args->n->buf)); */

    char* eff_response = args->n->buf; // 65536 bytes

    // getting number effective conn
    char tot_resp[20];
    snprintf (tot_resp, sizeof(tot_resp), "%d",total_accepted_connection);

    // constrcuting response
    int content_size = 201 + strlen(tot_resp);
    snprintf(eff_response, 1024, response, content_size , tot_resp);
    
    // sending
    write(args->socket, response, strlen(response));

    // simulate processing
    usleep(50);

    pthread_mutex_lock(&lock_queue);
    if(enqueue_buffer(args->n)) fprintf(stderr, "Error on enqueuing node\n");
    else pthread_cond_signal(&lastStateChange);
    pthread_mutex_unlock(&lock_queue);

    //close(args->socket);
    shutdown(args->socket, SHUT_WR);
    free(arg);
    return NULL;
}

int main(int argc, char** argv) {

    if (argc != 3) {
        printf("Error : 2 arguments needed (port, max num clients)\n");
        return 1;
    }

    int max_threads = atoi(argv[2]);

    struct addrinfo* address;
    mysocket = open_tcp_socket("0.0.0.0", argv[1], &address);

    // Now bind socket
    if (bind(mysocket, address->ai_addr, address->ai_addrlen)) {
        fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
	    return -1;
    }

    // Create queue
    create_queue_buffer(max_threads, MAX_RECV_SIZE);

    // Starting main loop
    printf("Supporting at most %d concurrent connections...\n", max_threads);

    if(listen(mysocket, max_threads) == -1) {                // Listen to the given file descriptor ; the 2nd parameter is the
        // length of the backlog of "pending connections"
        fprintf(stderr, "Could not listen: %s\n", strerror(errno));
        return -1;
    }

    total_accepted_connection = 0;

    while(1) {
        int connfd = accept(mysocket, (struct sockaddr*)NULL ,NULL); // accept awaiting request
        total_accepted_connection++;
        // Lock mutex to use queue
        pthread_mutex_lock(&lock_queue);
        node* n = dequeue_buffer();
        while (n == NULL) {
            pthread_cond_wait(&lastStateChange, &lock_queue);
            n = dequeue_buffer();
        }
        pthread_cond_signal(&lastStateChange);
        pthread_mutex_unlock(&lock_queue);

        printf("Concurent conn : %d. Total : %d\n", queue_max_size - queue_actual_size, total_accepted_connection);

        // Filling args
        thread_arg args = {n, connfd};
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
