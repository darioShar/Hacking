/**
 *  Jiazi Yi
 *
 * LIX, Ecole Polytechnique
 * jiazi.yi@polytechnique.edu
 *
 * Updated by Pierre Pfister
 *
 * Cisco Systems
 * ppfister@cisco.com
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "url.h"
#include "wgetX.h"

int main(int argc, char* argv[]) {
    url_info info;
    const char * file_name = "received_page.html";
    if (argc < 2) {
	fprintf(stderr, "Missing argument. Please enter URL.\n");
	return 1;
    }

    char *url = argv[1];

    // Get optional file name
    if (argc > 2) {
	file_name = argv[2];
    }

    char *response = NULL;

    // Download the page
    struct http_reply reply;

    int redirected = 0;
    char loc_redirection[MAX_URL_SIZE + 1];

    // Allow for up to max_redirect redirections
    int max_redirect = 10;
    int redirections = 0;
    do {
        // First parse the URL
        int ret = parse_url(url, &info);
        if (ret) {
	        fprintf(stderr, "Could not parse URL '%s': %s\n", url, parse_url_errstr[ret]);
            if (redirections > 0)
                break;
	        else 
                return 2;
        }

        //If needed for debug
        print_url_info(&info);

        ret = download_page(&info, &reply);
        if (ret) {
	        return 3;
        }

        // Now parse the responses. Also checks for possible redirection.
        response = read_http_reply(&reply, loc_redirection, MAX_URL_SIZE, &redirected);
        if (redirected) {
            printf("Redirection to url : %s\n", loc_redirection);
            url = loc_redirection;
        }
    }
    while(redirected && redirections++ < max_redirect);

    if (max_redirect < 0)
        printf("Maximum redirections reached. Saving server message...\n");

    if (response == NULL) {
        fprintf(stderr, "Could not parse http reply\n");
        return 4;
    }

    // Write response to a file
    printf("Writing data...\n");
    write_data(file_name, response, reply.reply_buffer + reply.reply_buffer_length - response);
    // Free allocated memory
    free(reply.reply_buffer);

    // Just tell the user where is the file
    fprintf(stderr, "the file is saved in %s.\n", file_name);
    return 0;
}

int download_page(url_info *info, http_reply *reply) {

    /*
     * To be completed:
     *   You will first need to resolve the hostname into an IP address.
     *
     *   Option 1: Simplistic
     *     Use gethostbyname function.
     *
     *   Option 2: Challenge
     *     Use getaddrinfo and implement a function that works for both IPv4 and IPv6.
     *
     */
    struct addrinfo* addresses; // linkedlist of returned adresses
    // (int)~0 is less than 32 characters in base 10
    char port[32];
    sprintf(port, "%d", info->port);
    int err = getaddrinfo(info->host, port, NULL, &addresses);
    if (err) {
        fprintf(stderr, "Could not get address. Error %d : %s\n", err, strerror(errno));
        // just return non zero for error
        return err;
    }

    // Now we have information in addresses.
    // Creating and connecting with socket. Reusing some client.c code given by the course.
    // Only trying with the first address in the linkedlist addrinfo.
    int mysocket = socket(AF_INET, SOCK_STREAM, 0);

    printf("Connecting to %s on port %s...\n", (char*)addresses->ai_addr->sa_data, port);
    if (connect(mysocket, addresses->ai_addr, addresses->ai_addrlen)) {
	    fprintf(stderr, "Could not connect: %s\n", strerror(errno));
        freeaddrinfo(addresses);
	    return -1;
    }
    printf("Connected.\n");

    /*
     * To be completed:
     *   Next, you will need to send the HTTP request.
     *   Use the http_get_request function given to you below.
     *   It uses malloc to allocate memory, and snprintf to format the request as a string.
     *
     *   Use 'write' function to send the request into the socket.
     *
     *   Note: You do not need to send the end-of-string \0 character.
     *   Note2: It is good practice to test if the function returned an error or not.
     *   Note3: Call the shutdown function with SHUT_WR flag after sending the request
     *          to inform the server you have nothing left to send.
     *   Note4: Free the request buffer returned by http_get_request by calling the 'free' function.
     *
     */
    char* request = http_get_request(info);
    printf("Sending request %s\n", request);
    err = write(mysocket, request, strlen(request));
    shutdown(mysocket, SHUT_WR);
    free(request);
    if (err == -1) {
        fprintf(stderr, "Could not write to server : %s\n", strerror(errno));
        freeaddrinfo(addresses);
        close(mysocket);
	    return -1;
    }
    printf("Request sent.\n");


    /*
     * To be completed:
     *   Now you will need to read the response from the server.
     *   The response must be stored in a buffer allocated with malloc, and its address must be save in reply->reply_buffer.
     *   The length of the reply (not the length of the buffer), must be saved in reply->reply_buffer_length.
     *
     *   Important: calling recv only once might only give you a fragment of the response.
     *              in order to support large file transfers, you have to keep calling 'recv' until it returns 0.
     *
     *   Option 1: Simplistic
     *     Only call recv once and give up on receiving large files.
     *     BUT: Your program must still be able to store the beginning of the file and
     *          display an error message stating the response was truncated, if it was.
     *
     *   Option 2: Challenge
     *     Do it the proper way by calling recv multiple times.
     *     Whenever the allocated reply->reply_buffer is not large enough, use realloc to increase its size:
     *        reply->reply_buffer = realloc(reply->reply_buffer, new_size);
     *
     *
     */
    printf("Waiting for data to be received...\n");
    int len = 0;
    int total_data = 0;
    reply->reply_buffer = malloc(CHUNK_SIZE);
    int buffer_size = CHUNK_SIZE;

    // Timer to know if we stop waiting for data
    int timer = clock() * 1000 / CLOCKS_PER_SEC;
    int no_data = 0;
    do {
        if (buffer_size < total_data + CHUNK_SIZE) {
            reply->reply_buffer = realloc(reply->reply_buffer, buffer_size + CHUNK_SIZE);
            buffer_size += CHUNK_SIZE;
        }
        len = recv(mysocket, reply->reply_buffer + total_data, CHUNK_SIZE, 0);
        total_data += len;

        // Breaks if no data has been sent for more than TIMEOUT_MS milliseconds.
        /*if(!len) {
            if (no_data && clock() * 1000 / CLOCKS_PER_SEC - timer > TIMEOUT_MS)
                break;
            no_data = 1;
        }
        else {
            no_data = 0;
            timer = clock() * 1000 / CLOCKS_PER_SEC;
        }*/
    }
    while(len > 0);

    reply->reply_buffer_length = total_data;

    printf("Data received : %d bytes\n", total_data);

    // We can now close socket and free memory
    close(mysocket);
    freeaddrinfo(addresses);

    // In case of error
    if (len < 0) {
	    fprintf(stderr, "recv returned error: %s\n", strerror(errno));
	    return -1;
    }

    //ok
    return 0;
}

void write_data(const char *path, const char * data, int len) {
    /*
     * To be completed:
     *   Use fopen, fwrite and fclose functions.
     */
    FILE* file = fopen(path, "wb");
    if (file == NULL) {
	    fprintf(stderr, "Could not open file %s : %s\n", path, strerror(errno));
	    return;
    }
    int total_written = fwrite(data, sizeof(char), len, file);
    if (len != total_written) {
        fprintf(stderr, "Only %d / %d bytes written on %s\n", total_written, len, path);
    }
    fclose(file);
}

char* http_get_request(url_info *info) {
    char * request_buffer = (char *) malloc(100 + strlen(info->path) + strlen(info->host));
    snprintf(request_buffer, 1024, "GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
	    info->path, info->host);
    return request_buffer;
}

char *next_line(char *buff, int len) {
    if (len <= 0) {
	return NULL;
    }

    char *last = buff + len - 1;
    while (buff != last) {
	if (*buff == '\r' && *(buff+1) == '\n') {
	    return buff;
	}
	buff++;
    }
    return NULL;
}



char *read_http_reply(struct http_reply *reply, char* loc_redirection, int max_url_size, int* redirected) {

    // Default case : no redirection
    *redirected = 0;

    // Let's first isolate the first line of the reply
    char *status_line = next_line(reply->reply_buffer, reply->reply_buffer_length);
    if (status_line == NULL) {
	fprintf(stderr, "Could not find status\n");
	return NULL;
    }
    *status_line = '\0'; // Make the first line is a null-terminated string

    // Now let's read the status (parsing the first line)
    int status;
    double http_version;
    int rv = sscanf(reply->reply_buffer, "HTTP/%lf %d", &http_version, &status);
    if (rv != 2) {
	fprintf(stderr, "Could not parse http response first line (rv=%d, %s)\n", rv, reply->reply_buffer);
	return NULL;
    }

    if (status != 200 && status != 301 && status != 302) {
	fprintf(stderr, "Server returned status %d. Unsupported\n", status);
	return NULL;
    }

    /*
     * To be completed:
     *   The previous code only detects and parses the first line of the reply.
     *   But servers typically send additional header lines:
     *     Date: Mon, 05 Aug 2019 12:54:36 GMT<CR><LF>
     *     Content-type: text/css<CR><LF>
     *     Content-Length: 684<CR><LF>
     *     Last-Modified: Mon, 03 Jun 2019 22:46:31 GMT<CR><LF>
     *     <CR><LF>
     *
     *   Keep calling next_line until you read an empty line, and return only what remains (without the empty line).
     *
     *   Difficul challenge:
     *     If you feel like having a real challenge, go on and implement HTTP redirect support for your client.
     *
     */

    // Now going through headers. Also looking for redirection if specified.
    int left_to_read = reply->reply_buffer_length;
    char* end_of_line = status_line; // remember we still have *status_line = '\0'
    char* buf = reply->reply_buffer; // to keep track of position in reply
    
    do {
        //  Updating left_to_read.
        left_to_read -= strlen(buf) - 2; // subtract the string length, '\0', '\n'
        buf = end_of_line + 2;

        // Going to next line
        end_of_line = next_line(buf, left_to_read);
        if (end_of_line == buf || end_of_line == NULL)
            break;
        
        // Looking for possible redirection, scanning new line
        *end_of_line = '\0';
        if (!*redirected && (status == 301 || status == 302)) {
            // Verifying url cannot be too big and then scanning
            if(strlen(buf) - sizeof("Location: ") <= max_url_size 
                && sscanf(buf, "Location: %s\n", loc_redirection) == 1) {
                // Success, we have new location, stored in loc_redirection.
                // Even if we will launch another request, continue to gte message received.
                *redirected = 1;
            }
        }
    }
    while(left_to_read >= 0);

    // if the given message was correctly formed, we have end_of_line == buf,
    // followed by \r\n
    if (end_of_line == buf) {
        return buf + 2;
    }

    // else there is a problem with the given string
    fprintf(stderr, "Error while reading received message, unsupported format.\n");
	return NULL;
}
