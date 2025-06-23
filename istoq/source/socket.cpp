#include <unistd.h>
#include <arpa/inet.h>
#include "../include/socket.h"

Socket::Socket(std::string log_path, int domain, int type, int protocol) : logger(log_path)
{
    socket_fd = socket(domain, type, protocol);
    if (socket_fd == -1)
        logger.log("Ошибка создания сокета", ERROR);
    else
    {
        logger.log("Сокет создан успешно", INFO);
    }
}