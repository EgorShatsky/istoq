#ifndef CLIENT_H
#define CLIENT_H

#include <cstring>
#include "../include/socket.h"
#include "../include/crypto.h"
#include "../include/utils.h"

class ClientSocket : public Socket 
{
public:
    ClientSocket(std::string log_path = "../log/client/client_log", int domain = AF_INET, int type = SOCK_STREAM, int protocol = 0) : Socket(log_path, domain, type, protocol) {}
    int connect(const char* ip, int port);
    // Используем socket_fd из базового класса
    int send(const char* msg) 
    {
        return ::send(socket_fd, msg, strlen(msg), 0);
    }
    int receive(char* buffer, size_t size) 
    {
        return recv(socket_fd, buffer, size, 0);
    }

     virtual ~ClientSocket() 
    {
        if (socket_fd != -1) 
        {
            close(socket_fd);
        }
    }
};

void process_info_message(ClientSocket& client, const char* payload, uint32_t size);
void process_key_container(
    ClientSocket& client, 
    KeyStorage& key_storage, 
    void* payload, 
    uint32_t size, 
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs
);
void proccess_kgenqpk(
    ClientSocket& client, 
    KeyStorage& key_storage, 
    void* payload, 
    uint32_t size, 
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs
);
void proccess_qk(
    ClientSocket& client, 
    KeyStorage& key_storage, 
    void* payload, 
    uint32_t size
);
void print_container_info(ClientSocket& client, Container& container);

#endif // CLIENT_H