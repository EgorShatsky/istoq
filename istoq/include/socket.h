#ifndef SOCKET_H
#define SOCKET_H

#include <arpa/inet.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include "../include/logger.h"

#define PORT 8080
#define IP "127.0.0.1"
#define BUFFER_SIZE 1024

class Socket 
{
// protected для доступа в наследниках (ClientSocket, ServerSocket)
protected:
    int socket_fd;
    sockaddr_in socket_addr;
public:
    Logger logger;
    Socket(std::string log_path = "../log/", int domain = AF_INET, int type = SOCK_STREAM, int protocol = 0);
    virtual ~Socket() 
    {
        if (socket_fd != -1) 
        {
            close(socket_fd);
        }
    }
    int get_socket_fd() const { return socket_fd; }
};

#endif // SOCKET_H