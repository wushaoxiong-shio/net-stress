#include <iostream>

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    int sockfd;
    struct sockaddr_in server_addr;
    const char *message = "Hello, UDP server!";
    
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        exit(EXIT_FAILURE);
    
    printf("Socket:%d\n",sockfd);

    while (1)
    {

    }

    return 0;
}