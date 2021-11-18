#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>

#define MAXRCVLEN 500

int main(int argc, char *argv[]) {
    char buffer[MAXRCVLEN + 1];
    int len, mysocket;
    struct sockaddr_in dest;

    mysocket = socket(AF_INET, SOCK_STREAM, 0);
    memset(&dest, 0, sizeof(dest));

    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dest.sin_port = htons(5000);

    if (connect(mysocket, (struct sockaddr *)&dest, sizeof(struct sockaddr))) {
	fprintf(stderr, "Could not connect: %s\n", strerror(errno));
	return -1;
    }

    len = recv(mysocket, buffer, MAXRCVLEN - 1, 0);
    if (len < 0) {
	fprintf(stderr, "recv returned error: %s\n", strerror(errno));
	return -1;
    }

    /*
     * Important note:
     *  TCP and UDP sockets are used to exchange bytes (a.k.a. octets), not strings.
     *  Nothing ensures a buffer that is received contains ASCII, UTF-8, or any other string encoding.
     *  It is protocol's job to specify what is the format of transmitted messages.
     *  And then it is a developer's job to make sure a program will not crash if some unexpected data is received.
     */


    buffer[len] = '\0';

    printf("Received %d bytes\n", len);
    int i;
    printf("Written as hex:");
    for (i = 0; i < len; i++) {
	if (i%16 == 0) {
	    printf("\n  ");
	}
	printf("%.2x ", buffer[i]);
    }
    printf("\n");

    printf("Written as a string: '%s'\n", buffer);

    close(mysocket);
    return 0;
}