#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define SA struct sockaddr
#define MAX_MSG_LEN 2048

// Original page :
// <!DOCTYPE html>
// <html>
// <head>
// <meta charset="utf-8" />
// <title>INF4743 | μ-challenge</title>
// </head>
// <body>
// <h1>MODAL HACK: μ-challenge</h1>
// <hr>
// <p>(Write you name in the below to show that you managed to hack this VM)</p>
// <p>Clément Gachod<p>
// </body>
// </html>



void process_connection(int conn_sock_fd, int *server_stay_alive) {
    printf("Connection accepted !\n");

    char buff[MAX_MSG_LEN];
    bzero(buff, MAX_MSG_LEN);
  
    // read the message from client and copy it in buffer
    read(conn_sock_fd, buff, sizeof(buff));

    if(strncmp(buff, "shutdown", 8) == 0) {
        *server_stay_alive = 0;
        return;
    }

    // Writing the buffer at the correct place in the html
    FILE *fp = fopen("/var/www/html/index.html", "w");
    fprintf(fp, "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\" />\n<title>INF4743 | μ-challenge</title>\n");
    fprintf(fp, "</head>\n<body>\n<h1>MODAL HACK: μ-challenge</h1>\n<hr>\n");
    fprintf(fp, "<p>(Write you name in the below to show that you managed to hack this VM)</p>\n");
    fprintf(fp, "%s\n", buff);
    fprintf(fp, "</body>\n</html>\n");
    fclose(fp);

    close(conn_sock_fd);
}


// Should return 0 on normal behavior
// https://www.geeksforgeeks.org/tcp-server-client-implementation-in-c/
int start_server(int port) {
    int serv_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (serv_sock_fd == -1) {
        printf("Server socket creation failed...\n");
        return 1;
    }
    else printf("Socket successfully created..\n");

    struct sockaddr_in servaddr, cliaddr;

    // Setting servaddr params after reset
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    // Binding newly created socket to given IP and verification
    if ((bind(serv_sock_fd, (SA *) &servaddr, sizeof(servaddr))) != 0) {
        printf("Server socket bind failed\n");
        return 1;
    }
    else printf("Server socket successfully binded...\n");
  
    // Now server is ready to listen and verification
    if ((listen(serv_sock_fd, 5)) != 0) {
        printf("Server socket listen failed\n");
        return 0;
    }
    else
        printf("Server socket listening...\n");


    int stay_alive = 1;
    unsigned int len = sizeof(cliaddr);

    while(stay_alive) {
        // Accept the data packet from client and verification
        int conn_sock_fd = accept(serv_sock_fd, (SA *) &cliaddr, &len);
        if (conn_sock_fd != 0)
            process_connection(conn_sock_fd, &stay_alive);
    }
  
    // After chatting close the socket
    close(serv_sock_fd);
    return 0;
}

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "Usage : server port_number\n");
        return 1;
    }

    int port = atoi(argv[1]);
    start_server(port);
}