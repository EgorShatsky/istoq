#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <array>
#include "spbpkcs11.h"
#include "../include/server.h"
#include "../include/crypto.h"
#include "../include/utils.h"

ServerSocket::ServerSocket(std::string log_path, int domain, int type, int protocol) : Socket(log_path, domain, type, protocol)
{
    server_fd = socket(domain, type, protocol);
    if (server_fd == -1)
    {
        logger.log("Ошибка создания сокета", ERROR);
    }
    else
    {
        logger.log("Сокет сервера создан успешно", INFO);
    }
}

int ServerSocket::bind(int port)
{
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_addr.s_addr = INADDR_ANY;
    socket_addr.sin_port = htons(port);
    return ::bind(server_fd, (sockaddr*)&socket_addr, sizeof(socket_addr));
}

int ServerSocket::accept()
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    return ::accept(server_fd, (sockaddr*)&client_addr, &addr_len);
}

// Цикл ввода команд в терминал сервера
void input_cmd_loop(std::atomic<bool>& running, ServerSocket& server, std::vector<pollfd>& poll_fds)
{
    while (running)
    {
        std::string cmd;
        std::cout << "SERVER: ";
        getline(std::cin, cmd);
        if (cmd.find("EXIT") == 0)
        {
            server.logger.log("Завершение работы сервера", INFO);
            server.logger.log("Размер poll: " + std::to_string(poll_fds.size()), INFO);

            if (poll_fds.size() > 1)
            {
                server.logger.log("Кол-во клиентов на сервере: " + std::to_string(poll_fds.size() - 1), INFO);
                for (size_t i = 1; i < poll_fds.size(); i++)
                {
                    std::string str = "STOP";
                    std::vector<char> buffer(str.size() + 1, 0);
                    std::copy(str.begin(), str.end(), buffer.begin());
                    send_cmd(&server, poll_fds[i].fd, buffer.data(), buffer.size());
                    close(poll_fds[i].fd);
                }
                running = false;
            }
            else
            {
                server.logger.log("Нет подключенных клиентов, сервер остановлен", INFO);
                running = false;
            }
        }
        else
        {
            server.logger.log("Некорректная команда сервера", INFO);
            continue;
        }
    }
}

// Цикл проверки файловых дескрипторов на события
void poll_loop(std::atomic<bool>& running, ServerSocket& server, std::vector<pollfd>& poll_fds, std::unordered_map<int, KeyStorage>& server_key_storage, std::unordered_map<int, ClientID>& client_info, CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs, CK_BYTE_PTR server_id)
{
    while (running) 
    {
        int active = poll(poll_fds.data(), poll_fds.size(), 100);
        if (!running) break;
        if (active < 0) 
        {
            server.logger.log("Ошибка poll", ERROR);
            break;
        }

        for (size_t i = 0; i < poll_fds.size(); ++i) 
        {
            if (poll_fds[i].revents & POLLIN) 
            {
                // Если на сервер что то пришло
                if (poll_fds[i].fd == server.get_socket_fd())
                {
                    CK_RV rv = CKR_OK;
                    int client_socket = server.accept();
                    if (client_socket == -1)
                    {
                        server.logger.log("Ошибка принятия подключения", ERROR);
                        continue;
                    }

                    ClientID client_id_struct;
                    rv = C_GenerateRandom(session, client_id_struct.id, 16);
                    client_info.emplace(client_socket, client_id_struct);

                    // Тут происходит первоначальное подключение клиента
                    poll_fds.push_back({client_socket, POLLIN, 0});
                   
                    server.logger.log ("Подключение клиента (ID): " + std::to_string(client_socket),  INFO);

                    // Для клиента нужно создать хранилище ключей
                    KeyStorage client_key_storage;
                    server_key_storage[client_socket] = client_key_storage;

                    // У каждого клиента изначально должна быть следующая ключевая инфрмация
                    // KGenQPK, KQPK, QK
                    KeyInfo kgenqpk_base_key_info;
                    CK_BYTE kgenqpk_base[32] = {0};
                    CK_BYTE kgenqpk_base_id[16] = {0};
                    CK_BYTE kgenqpk_base_use_ctr[8] = {0};
                    key_gen_256(session, funcs, kgenqpk_base); // Генерация KGenQPK
                    if (rv != CKR_OK) { server.logger.log("Ошибка генерации ключа KGenQPK", ERROR); }
                    rv = C_GenerateRandom(session, kgenqpk_base_id, 16); // Генерация id
                    if (rv != CKR_OK) { server.logger.log("Ошибка генерации id ключа KGenQPK", ERROR); }
                    memcpy(kgenqpk_base_key_info.key_id, kgenqpk_base_id, 16);
                    memcpy(kgenqpk_base_key_info.key_value, kgenqpk_base, 32);
                    memcpy(kgenqpk_base_key_info.key_ctr, kgenqpk_base_use_ctr, 8);

                    KeyInfo qk_info;
                    CK_BYTE qk[32] = {0};
                    CK_BYTE qk_id[16] = {0};
                    CK_BYTE qk_use_ctr[8] = {0};
                    key_gen_256(session, funcs, qk); // Генерация QK
                    if (rv != CKR_OK) { server.logger.log("Ошибка генерации ключа QK", ERROR); }
                    rv = C_GenerateRandom(session, qk_id, 16); // Генерация id
                    if (rv != CKR_OK) { server.logger.log("Ошибка генерации id ключа QK", ERROR); }
                    memcpy(qk_info.key_id, qk_id, 16);
                    memcpy(qk_info.key_value, qk, 32);
                    memcpy(qk_info.key_ctr, qk_use_ctr, 8);
                    
                    KeyInfo kgenqpk_derive_key_info;
                    CK_BYTE kgenqpk_derive[32] = {0};
                    CK_BYTE kgenqpk_derive_id[16] = {0};
                    CK_BYTE kgenqpk_derive_use_ctr[8] = {0};
                    rv = C_GenerateRandom(session, kgenqpk_derive_id, 16); // Генерация id
                    if (rv != CKR_OK) { server.logger.log("Ошибка генерации id производного ключа KGenQPK", ERROR); }

                    KeyInfo kqpk_key_info;
                    CK_BYTE kqpk[32] = {0};
                    CK_BYTE kqpk_id[16] = {0};
                    CK_BYTE kqpk_use_ctr[8] = {0};
                    rv = C_GenerateRandom(session, kqpk_id, 16); // Генерация id
                    if (rv != CKR_OK) { server.logger.log("Ошибка генерации id ключа KQPK", ERROR); }
                    
                    // На основе ключа генерации ключа защиты компоненты генерируем два ключа
                    kdf1(session, funcs, kgenqpk_base, kgenqpk_base_use_ctr, kgenqpk_derive, kqpk);
                    server.logger.log("Диверсификация ключей выполнена успешно (ID):" + std::to_string(client_socket), INFO);

                    memcpy(kgenqpk_derive_key_info.key_id, kgenqpk_derive_id, 16);
                    memcpy(kgenqpk_derive_key_info.key_value, kgenqpk_derive, 32);
                    memcpy(kgenqpk_derive_key_info.key_ctr, kgenqpk_derive_use_ctr, 8);

                    memcpy(kqpk_key_info.key_id, kqpk_id, 16);
                    memcpy(kqpk_key_info.key_value, kqpk, 32);
                    memcpy(kqpk_key_info.key_ctr, kqpk_use_ctr, 8);

                    // Теперь нужно добавить ключи в ключевое хранилище
                    server_key_storage[client_socket].add_key(KeyType::KGenQPK, kgenqpk_base_key_info);
                    server_key_storage[client_socket].add_key(KeyType::KQPK, kqpk_key_info);
                    server_key_storage[client_socket].add_key(KeyType::QK, qk_info);
                    server.logger.log("Первоначальное распределение ключей выполнено успешно (ID):" + std::to_string(client_socket), INFO);

                    // Вывод ключей
                    std::string kgenqpk_str = bytes_to_hex_string(server_key_storage[client_socket].get_key_value(KeyType::KGenQPK), 32);
                    std::string kqpk_str = bytes_to_hex_string(server_key_storage[client_socket].get_key_value(KeyType::KQPK), 32);
                    std::string qk_str = bytes_to_hex_string(server_key_storage[client_socket].get_key_value(KeyType::QK), 32);

                    server.logger.log("KGenQPK: " + kgenqpk_str, INFO);
                    server.logger.log("KQPK: " + kqpk_str, INFO);
                    server.logger.log("QK: " + qk_str, INFO);

                    // Отправка ключа KGenQPK на клиент
                    send_key(&server, 0x04, client_socket, &kgenqpk_base_key_info);

                    // Отправка ключа QK на клиент
                    send_key(&server, 0x05, client_socket, &qk_info);
                    
                    std::string str = "Успешное подключение с серверу";
                    std::vector<char> buffer(str.size() + 1, 0);
                    std::copy(str.begin(), str.end(), buffer.begin());
                    send_info(&server, client_socket, buffer.data(), str.size());
                }
                else 
                {
                    // Обработка данных от клиента
                    int client_socket = poll_fds[i].fd;
                    char buffer[BUFFER_SIZE] = {0};

                    int bytes_read = server.receive(client_socket, buffer, BUFFER_SIZE);
                    if (bytes_read <= 0) 
                    {
                        shutdown(poll_fds[i].fd, SHUT_RDWR);
                        close(poll_fds[i].fd);
                        poll_fds.erase(poll_fds.begin() + i);
   
                        // Клиент отключился
                        close(client_socket);
                        poll_fds.erase(poll_fds.begin() + i);
                        client_info.erase(client_socket);  // Добавить эту строку
                        --i;
                        server.logger.log ("Клиент отключен (ID): " + std::to_string(client_socket),  INFO);
                        continue;
                    }

                    std::string message(buffer, bytes_read);

                    // Обработка запросов от клиентов 
                    if (message.find("GET KEY") == 0) 
                    {
                        server.logger.log("Запрос на получение ключа от (ID): " + std::to_string(client_socket),  INFO);
                        // Если пользователь прислал только GET_KEY
                        if (message.size() == 7)
                        {
                            server.logger.log("Некорректный запрос на получение ключа!",  INFO);
                            continue;
                        }

                        // Выделяем строку после команды
                        std::string raw_id(message, 7, message.size());
                        std::string id;

                        // На первой позиции обязательно пробел
                        if (raw_id[0] != ' ')
                        {
                            server.logger.log ("Некорректно введен ID другого пользователя!",  INFO);
                            continue;
                        }
               
                        int space_pos = raw_id.substr(1).find_first_of(' ');
                        id = raw_id.substr(1, space_pos);

                        // Проверка валидный id или нет
                        bool convert_flag = 1;
                        for (size_t i = 0; i < id.size(); i++)
                        {
                            if (!isdigit(id.at(i)))
                            {
                                server.logger.log ("Некорректно введен ID другого пользователя!",  INFO);
                                convert_flag = 0;
                                break;
                            }
                        }

                        // Если нельзя конвертировать
                        if (convert_flag == 0)
                        {
                            continue;
                        }
                
                        // Если можно конвертировать в число
                        int second_client_socket = atoi(id.c_str());
                        bool connected = 0;

                        // Проверка есть ли сокет в poll
                        for (size_t i = 1; i < poll_fds.size(); i++)
                        {
                            if (poll_fds[i].fd == second_client_socket)
                            {
                                CK_RV rv = CKR_OK;
                                server.logger.log ("Пользователь с указанным ID подключен к серверу!",  INFO);
                                connected = 1;
                                KeyInfo rand_comp_key_info;
                                CK_BYTE rand_comp[32] = {0};
                                CK_BYTE rand_comp_id[16] = {0};
                                CK_BYTE rand_comp_use_ctr[8] = {0};
                                key_gen_256(session, funcs, rand_comp); // Генерация компоненты Rand
                                if (rv != CKR_OK) { server.logger.log("Ошибка генерации компоненты Rand", ERROR); }
                                rv = C_GenerateRandom(session, rand_comp_id, 16); // Генерация id
                                if (rv != CKR_OK) { server.logger.log("Ошибка генерации id компоненты Rand", ERROR); }
                                memcpy(rand_comp_key_info.key_id, rand_comp_id, 16);
                                memcpy(rand_comp_key_info.key_value, rand_comp, 32);
                                memcpy(rand_comp_key_info.key_ctr, rand_comp_use_ctr, 8);

                                KeyInfo qrand_comp_key_info;
                                CK_BYTE qrand_comp[32] = {0};
                                CK_BYTE qrand_comp_id[16] = {0};
                                CK_BYTE qrand_comp_use_ctr[8] = {0};
                                key_gen_256(session, funcs, qrand_comp); // Генерация компоненты QRand
                                if (rv != CKR_OK) { server.logger.log("Ошибка генерации компоненты QRand", ERROR); }
                                rv = C_GenerateRandom(session, qrand_comp_id, 16); // Генерация id
                                if (rv != CKR_OK) { server.logger.log("Ошибка генерации id компоненты QRand", ERROR); }
                                memcpy(qrand_comp_key_info.key_id, qrand_comp_id, 16);
                                memcpy(qrand_comp_key_info.key_value, qrand_comp, 32);
                                memcpy(qrand_comp_key_info.key_ctr, qrand_comp_use_ctr, 8);

                                server_key_storage[client_socket].add_key(KeyType::Rand, rand_comp_key_info);
                                server_key_storage[client_socket].add_key(KeyType::QRand, qrand_comp_key_info);

                                std::string rand_str = bytes_to_hex_string(server_key_storage[client_socket].get_key_value(KeyType::Rand), 32);
                                std::string qrand_str = bytes_to_hex_string(server_key_storage[client_socket].get_key_value(KeyType::QRand), 32);
                                server.logger.log("Rand: " + rand_str, INFO);
                                server.logger.log("QRand: " + qrand_str, INFO);

                                // Все необходимые ключи находятся в KeyStorage
                                CK_BYTE id_qpk[6] = {0};   // ID набора целевых ключей
                                rv = C_GenerateRandom(session, id_qpk, 6);
                                if (rv != CKR_OK) { server.logger.log("Ошибка генерации id набора ЦК", ERROR); }
                            
                                CK_BYTE cs_kw[1] = {0x00}; // Экспортное представление - "Кузнечик
                          
                                Container rand_container;
                                CK_BYTE rand_label[8] = {0x00, 0x00, 0x00, 0x00, 0x4B, 0x51, 0x50, 0x4B};

                                Container qrand_container;
                                CK_BYTE qrand_label[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x4B};

                                // Заполнение информации контейнера компоненты Rand
                                memcpy(rand_container.label, rand_label, 8);
                                memcpy(rand_container.m, id_qpk, 6);
                                memcpy(rand_container.cs_kw, cs_kw, 1);
                                memcpy(rand_container.id_base_key, server_key_storage[client_socket].get_key_id(KeyType::KQPK), 16);
                                memcpy(rand_container.cs_kw, cs_kw, 1);
                                memcpy(rand_container.use_key_ctr, server_key_storage[client_socket].get_key_ctr(KeyType::KQPK), 8);

                                // Заполнение информации контейнера компоненты QRand
                                memcpy(qrand_container.label, qrand_label, 8);
                                memcpy(qrand_container.m, id_qpk, 6);
                                memcpy(qrand_container.cs_kw, cs_kw, 1);
                                memcpy(qrand_container.id_base_key, server_key_storage[client_socket].get_key_id(KeyType::QK), 16);
                                memcpy(qrand_container.cs_kw, cs_kw, 1);
                                memcpy(qrand_container.use_key_ctr, server_key_storage[client_socket].get_key_ctr(KeyType::QK), 8);

                                // Id клиента инициатора
                                memcpy(rand_container.dpu_id_initiator, client_info[client_socket].id, 16);
                                memcpy(qrand_container.dpu_id_initiator, client_info[client_socket].id, 16);

                                // Id клиента второго
                                memcpy(rand_container.dpu_id_initiator_pair, client_info[second_client_socket].id, 16);
                                memcpy(qrand_container.dpu_id_initiator_pair, client_info[second_client_socket].id, 16);

                                // Id сервера 
                                memcpy(rand_container.dpu_id_sender, server_id, 16);
                                memcpy(qrand_container.dpu_id_sender, server_id, 16);

                                // Id получателя
                                memcpy(rand_container.dpu_id_receiver, client_info[client_socket].id, 16);
                                memcpy(qrand_container.dpu_id_receiver, client_info[client_socket].id, 16);
                                
                                // Формирование экспортного представления Rand
                                CK_ULONG rand_kexp_size = 48;
                                CK_BYTE rand_kexp[48] = {0};
                                kexp15_kuzn(
                                    session, 
                                    funcs, 
                                    server_key_storage[client_socket].get_key_value(KeyType::KQPK), 
                                    32, 
                                    server_key_storage[client_socket].get_key_value(KeyType::Rand),
                                    32, 
                                    server_key_storage[client_socket].get_key_ctr(KeyType::KQPK), 
                                    8, 
                                    rand_kexp, 
                                    &rand_kexp_size
                                );

                                // Формирование экспортного представления QRand
                                CK_ULONG qrand_kexp_size = 48;
                                CK_BYTE qrand_kexp[48] = {0};
                                kexp15_kuzn(
                                    session, 
                                    funcs, 
                                    server_key_storage[client_socket].get_key_value(KeyType::QK), 
                                    32, 
                                    server_key_storage[client_socket].get_key_value(KeyType::QRand),
                                    32, 
                                    server_key_storage[client_socket].get_key_ctr(KeyType::QK), 
                                    8, 
                                    qrand_kexp, 
                                    &qrand_kexp_size
                                );

                                // Добавление kexp в контейнер
                                memcpy(rand_container.kexp, rand_kexp, 48);
                                memcpy(qrand_container.kexp, qrand_kexp, 48);

                                print_container_info(&server, &rand_container);
                                server.logger.log("===========================================", INFO);
                                print_container_info(&server, &qrand_container);

                                // Отправить контейнер первому клиенту
                                send_container(&server, client_socket, &rand_container, sizeof(Container));
                                send_container(&server, client_socket, &qrand_container, sizeof(Container));

                                // Теперь нужно на других ключах зашифровать контейнеры и отправить второму клиенту
                                // Получатель теперь другой 
                                memset(rand_container.dpu_id_receiver, 0, 16);
                                memset(qrand_container.dpu_id_receiver, 0, 16);
                                memcpy(rand_container.dpu_id_receiver, client_info[second_client_socket].id, 16);
                                memcpy(qrand_container.dpu_id_receiver, client_info[second_client_socket].id, 16);

                                // kexp тоже меняется так, как зашифрование происходит на других ключах
                                memset(rand_container.kexp, 0, 48);
                                memset(qrand_container.kexp, 0, 48);
                                memset(rand_kexp, 0, 48);
                                memset(qrand_kexp, 0, 48);

                                kexp15_kuzn(
                                    session, 
                                    funcs, 
                                    server_key_storage[second_client_socket].get_key_value(KeyType::KQPK), 
                                    32, 
                                    server_key_storage[client_socket].get_key_value(KeyType::Rand),
                                    32, 
                                    server_key_storage[second_client_socket].get_key_ctr(KeyType::KQPK), 
                                    8, 
                                    rand_kexp, 
                                    &rand_kexp_size
                                );

                                // Формирование экспортного представления QRand
                                kexp15_kuzn(
                                    session, 
                                    funcs, 
                                    server_key_storage[second_client_socket].get_key_value(KeyType::QK), 
                                    32, 
                                    server_key_storage[client_socket].get_key_value(KeyType::QRand),
                                    32, 
                                    server_key_storage[second_client_socket].get_key_ctr(KeyType::QK), 
                                    8, 
                                    qrand_kexp, 
                                    &qrand_kexp_size
                                );

                                // Добавление kexp в контейнер
                                memcpy(rand_container.kexp, rand_kexp, 48);
                                memcpy(qrand_container.kexp, qrand_kexp, 48);

                                // Отправить контейнер второму клиенту
                                send_container(&server, second_client_socket, &rand_container, sizeof(Container));
                                send_container(&server, second_client_socket, &qrand_container, sizeof(Container));
                            }
                        }
                        if (connected == 0)
                        {
                            server.logger.log ("Пользователь с указанным ID не подключен к серверу!",  INFO);
                        }

                        continue;
                    }
                    else if (message.find("LIST") == 0)
                    {
                        server.logger.log ("Запрос на получение списка подключенных клиентов (ID): " + std::to_string(client_socket),  INFO);
                        std::string list;
                        
                        // первый в векторе poll_fds - fd сервера
                        for (size_t i = 1; i < poll_fds.size(); i++)
                        {
                            if (poll_fds[i].fd != client_socket)
                            {
                                list = list + "ID: " + std::to_string(poll_fds[i].fd) + ",";
                            }
                        }

                        // Удаляем последнюю запятую
                        if (!list.empty())
                        {
                            list.pop_back();
                        }
                    
                        if (list.empty())
                        {
                            list = "Вы единственный подключенный клиент в данный момент";
                        }

                        std::vector<char> buffer(list.size() + 1, 0);
                        std::copy(list.begin(), list.end(), buffer.begin());

                        send_info(&server, client_socket, buffer.data(), list.size());
                        continue;
                    }
                    else if (message.find("STOP") == 0)
                    {
                        server.logger.log("Клиент прислал запрос на отключение (ID): " + std::to_string(client_socket),  INFO);
                        std::string str = "OK";
                        std::vector<char> buffer(str.size() + 1, 0);
                        std::copy(str.begin(), str.end(), buffer.begin());
                        send_info(&server, client_socket, buffer.data(), str.size());
                        close(client_socket);
                        server.logger.log ("Клиент отключился (ID): " + std::to_string(client_socket),  INFO);
                        poll_fds.erase(poll_fds.begin() + i);
                        --i;
                        continue;
                    }
                    else
                    {
                        server.logger.log ("Некорректная команда (ID): " + std::to_string(client_socket),  INFO);
                        continue;
                    }
                }
            }
        }
    }
}

void print_container_info(ServerSocket* server, Container* container)
{
    server->logger.log("label: " + bytes_to_hex_string(container->label, 8), INFO);
    server->logger.log("id QPK: " + bytes_to_hex_string(container->m, 6), INFO);
    server->logger.log("cs_cw: " + bytes_to_hex_string(container->cs_kw, 1), INFO);
    server->logger.log("id_base_key: " + bytes_to_hex_string(container->id_base_key, 16), INFO);
    server->logger.log("use_key_ctr: " + bytes_to_hex_string(container->use_key_ctr, 8), INFO);
    server->logger.log("dpu_id_initiator: " + bytes_to_hex_string(container->dpu_id_initiator, 16), INFO);
    server->logger.log("dpu_id_initiator_pair: " + bytes_to_hex_string(container->dpu_id_initiator_pair, 16), INFO);
    server->logger.log("dpu_id_sender: " + bytes_to_hex_string(container->dpu_id_sender, 16), INFO);
    server->logger.log("dpu_id_reciever: " + bytes_to_hex_string(container->dpu_id_receiver, 16), INFO);
    server->logger.log("kexp: " + bytes_to_hex_string(container->kexp, 48), INFO);
}

// Отправка информационного сообщения с сервера
int send_info(ServerSocket* server, int client_fd, char* str, size_t str_size) 
{
    Message msg;
    msg.type = 0x01; // INFO
    msg.payload_size = static_cast<uint32_t>(str_size); // Длина отправляемых данных

    // Очищаем буфер перед использованием
    memset(msg.payload, 0, sizeof(msg.payload));
    // Копируем только необходимое количество данных
    memcpy(msg.payload, str, std::min(str_size, sizeof(msg.payload)));

    server->logger.log("message type: " + std::to_string(msg.type), INFO);
    server->logger.log("message payload size: " + std::to_string(msg.payload_size), INFO);
    
    if (server->send(client_fd, &msg, sizeof(Message)) == - 1)
    {
        server->logger.log("Ошибка отправки информационного сообщения (ID): " + std::to_string(client_fd), ERROR);
        return -1;
    }
    else
    {
        server->logger.log("Информационное сообщение отправлено успешно (ID): " + std::to_string(client_fd), INFO);
        return 0;
    }
}

int send_cmd(ServerSocket* server, int client_fd, char* str, size_t str_size)
{
    Message msg;
    msg.type = 0x02; // Command
    msg.payload_size = static_cast<uint32_t>(str_size); // Длина отправляемых данных

    // Очищаем буфер перед использованием
    memset(msg.payload, 0, sizeof(msg.payload));

    // Копируем только необходимое количество данных
    memcpy(msg.payload, str, std::min(str_size, sizeof(msg.payload)));

    server->logger.log("message type: " + std::to_string(msg.type), INFO);
    server->logger.log("message payload size: " + std::to_string(msg.payload_size), INFO);

    if (server->send(client_fd, &msg, sizeof(Message)) == - 1)
    {
        server->logger.log("Ошибка отправки команды (ID): " + std::to_string(client_fd), ERROR);
        return -1;
    }
    else
    {
        server->logger.log("Команда отправлена успешно (ID): " + std::to_string(client_fd), INFO);
        return 0;
    }
}

// Отправка ключевого контейнера
int send_container(ServerSocket* server, int client_fd, Container* container, size_t container_size)
{
    Message msg;

    // Очищаем буфер перед использованием
    memset(msg.payload, 0, sizeof(msg.payload));
    memset(&msg.type, 0, sizeof(msg.type));
    memset(&msg.payload_size, 0, sizeof(msg.payload_size));

    msg.type = 0x03; // Containter
    msg.payload_size = static_cast<uint32_t>(sizeof(Container)); // Длина отправляемых данных

    // Копируем только необходимое количество данных
    memcpy(msg.payload, container, std::min(container_size, sizeof(msg.payload)));

    server->logger.log("message type: " + std::to_string(msg.type), INFO);
    server->logger.log("message payload size: " + std::to_string(msg.payload_size), INFO);

    if (server->send(client_fd, &msg, sizeof(Message)) == - 1)
    {
        server->logger.log("Ошибка отправки контейнера (ID): " + std::to_string(client_fd), ERROR);
        return -1;
    }
    else
    {
        server->logger.log("Контейнер отправлен успешно (ID): " + std::to_string(client_fd), INFO);
        return 0;
    }
}

// Отправка ключевого контейнера
int send_key(ServerSocket* server, uint8_t type, int client_fd, KeyInfo* key_info)
{
    Message msg;
    msg.type = type; // 0x04 - KGenQPK
    msg.payload_size = static_cast<uint32_t>(sizeof(KeyInfo));
 
    // Очищаем буфер перед использованием
    memset(msg.payload, 0, sizeof(msg.payload));

    // Копируем только необходимое количество данных
    memcpy(msg.payload, key_info, msg.payload_size);

    server->logger.log("message type: " + std::to_string(msg.type), INFO);
    server->logger.log("message payload size: " + std::to_string(msg.payload_size), INFO);

    if (server->send(client_fd, &msg, sizeof(Message)) == - 1)
    {
        server->logger.log("Ошибка отправки первоначальных ключей (ID): " + std::to_string(client_fd), ERROR);
        return -1;
    }
    else
    {
        server->logger.log("Первоначальные ключи отправлены успешно (ID): " + std::to_string(client_fd), INFO);
        return 0;
    }
}

int main()
{
    ServerSocket server;
    server.bind(PORT);
    server.listen(MAX_CLIENTS);

    std::atomic<bool> running{true};

    // Инициализация библиотеки pkcs11
    // удалено 2 строчки
    CK_FUNCTION_LIST_PTR funcs = handle.functionList(); // получение списка функций

    // Массив fd pollfd для оповещений о событиях
    std::vector<pollfd> poll_fds;

    // ID сервера
    CK_BYTE server_id[16] = {0};
    C_GenerateRandom(handle.session(), server_id, 16);
    std::string str_server_id = bytes_to_hex_string(server_id, 16);

    // Хранилище ключей сервера <client_fd, KeyStorage>
    std::unordered_map<int, KeyStorage> server_key_storage;
    std::unordered_map<int, ClientID> client_info;

    // Добавляем fd сервера в пул
    poll_fds.push_back({server.get_socket_fd(), POLLIN, 0});
    server.logger.log("Сервер запущен на порту: " + std::to_string(PORT), INFO);
    server.logger.log("ID сервера: " + str_server_id, INFO);
   
    std::thread cmd_thread(
        input_cmd_loop, 
        std::ref(running),
        std::ref(server), 
        std::ref(poll_fds)
    );

    std::thread poll_thread(
        poll_loop, 
        std::ref(running),
        std::ref(server), 
        std::ref(poll_fds), 
        std::ref(server_key_storage), 
        std::ref(client_info), 
        handle.session(), 
        funcs, server_id
    );

    cmd_thread.join();
    poll_thread.join();
}