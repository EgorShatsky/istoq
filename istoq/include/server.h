#ifndef SERVER_H
#define SERVER_H

#include <unordered_map>
#include <cstring>
#include "spbpkcs11.h"
#include "../include/socket.h"

#define PORT 8080
#define MAX_CLIENTS 10

struct Container;
struct KeyStorage;
struct KeyInfo;

struct ClientID {
    CK_BYTE id[16];
    
    // Для работы с unordered_map
    bool operator==(const ClientID& other) const 
    {
        return memcmp(id, other.id, 16) == 0;
    }
};

// Хэш-функция для ClientID
namespace std {
    template<> 
    struct hash<ClientID> 
    {
        size_t operator()(const ClientID& k) const 
        {
            return hash<string>()(string(reinterpret_cast<const char*>(k.id), 16));
        }
    };
}

class ServerSocket : public Socket
{
public:
    ServerSocket(std::string path = "../log/server/server_log", int domain = AF_INET, int type = SOCK_STREAM, int protocol = 0);

    virtual ~ServerSocket() 
    {
        if (server_fd != -1) 
        {
            close(server_fd);
        }
    }

    int get_socket_fd() const { return server_fd; }

    int bind(int port);

    int listen(int max_client)
    {
        return ::listen(server_fd, max_client);
    }

    int accept();

    // Используем socket_fd из базового класса
    int send(int client_fd, const void* msg, size_t msg_len) 
    {
        return ::send(client_fd, msg, msg_len, 0);
    }

    int receive(int client_fd, char* buffer, size_t size) 
    {
        return recv(client_fd, buffer, size, 0);
    }
    
private:
    int server_fd;
    sockaddr_in socket_addr; 
};

// Отправка пакетов на клиент
int send_info(ServerSocket* server, int client_fd, char* str, size_t str_size);
int send_cmd(ServerSocket* server, int client_fd, char* str, size_t str_size);
int send_container(ServerSocket* server, int client_fd, Container* container, size_t container_size);
int send_key(ServerSocket* server, uint8_t type, int client_fd, KeyInfo* key_info);
void print_container_info(ServerSocket* server, Container* container);

#endif // SERVER_H