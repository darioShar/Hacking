#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

int main(void) {
    int listenfd = 0, connfd = 0;         // "fd" literally means "file descriptor", and is simply an identifier (int)
					  // used in C for identifying an "input/output point"
    struct sockaddr_in serv_addr;         // sockaddr_in is, with in_addr, the two basic data structures for
					  // network connection mgmt. and Internet addresses.
    char sendBuff[1025];

    listenfd = socket(AF_INET, SOCK_STREAM, 0); // socket(...) creates an end-point for communication
						// AF_INET     - literally "Address Family = Internet" (IPv4);
						// SOCK_STREAM - Stream (TCP) socket
						// The last argument, 0,"what protocol is being used", and is
						// there as a matter of principle. Most often, it will be 0, which
						// means "there be only one"
    printf("Socket created\n");

    memset(&serv_addr, 0, sizeof(serv_addr)); // memset(arg1, arg2, arg3) essentially fills a chunk of memory
    memset(sendBuff, 0, sizeof(sendBuff));    // of size arg3, staring at arg1, with a sequence of arg2.

    serv_addr.sin_family = AF_INET;                // Populate the struct sockaddr_in with "use IPv4"
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // htonl converts a long "from host to network byte order"
						   // INADDR_ANY indicates to bind the socket to all local interfaces
						   // An alternative could be to say
						   // serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(5000);              // htons converts a short "from host to network byte order"

    // At this time, the data structures have been set up -- now to tie it all together

    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) { // bind the socket to the requested address and port.
	fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
	return -1;
    }

    if(listen(listenfd, 10) == -1) {                // Listen to the given file descriptor ; the 2nd parameter is the
	// length of the backlog of "pending connections"
	fprintf(stderr, "Could not listen: %s\n", strerror(errno));
	return -1;
    }

    const char* response = "HTTP/1.1 302 Found\r\n\
Location: http://localhost:5000/\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Content-Length: 218\r\n\
Date: Thu, 15 Sep 2011 07:00:20 GMT\r\n\
Server: gws\r\n\
Content-Length: 218\r\n\
X-XSS-Protection: 1; mode=block\r\n\
\r\n\
<......the HTML page .....>";

    while(1) {
	connfd = accept(listenfd, (struct sockaddr*)NULL ,NULL); // accept awaiting request
	strcpy(sendBuff, response);
	write(connfd, sendBuff, strlen(sendBuff)); // write does what you'd expect:
						   // it writes arg3 octets from arg2 into arg1 file descriptor
	close(connfd);                             // ALWAYS remember to close a connection when done.
    }

    return 0;
}