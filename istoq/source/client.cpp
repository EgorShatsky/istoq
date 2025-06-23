#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <iostream>
#include <thread>
#include <cstring>
#include <cinttypes>
#include <iomanip>
#include <sstream>
#include <vector>
#include "spbpkcs11.h"
#include "../include/client.h"
#include "../include/crypto.h"

int ClientSocket::connect(const char* ip, int port)
{
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &socket_addr.sin_addr) <= 0) 
    {
        logger.log("Неверный адрес", ERROR);
        return -1;
    }
    return ::connect(socket_fd, 
                   (struct sockaddr*)&socket_addr, 
                   sizeof(socket_addr));
}

// Считываем то, что ввел клиент
void input_cmd_loop(ClientSocket& client)
{
    while (true)
    {
        std::string cmd;
        std::cout << "CLIENT: ";
        getline(std::cin, cmd);

        if (cmd.find("STOP") == 0)
        {
            client.send(cmd.c_str());
            client.logger.log("Отключение сервера и завершение работы клиента", INFO);
            client.~ClientSocket();
            exit(0);
        }
        else if (cmd.find("LIST") == 0)
        {   
            client.send(cmd.c_str());
            client.logger.log("Отправка команды на получение списка ДПУ", INFO);
            cmd.clear();
            continue;
        } 
        else if (cmd.find("GET KEY") == 0)
        {   
            client.send(cmd.c_str());
            client.logger.log("Отправка команды на получение ключа", INFO);
            cmd.clear();
            continue;
        } 
        else
        {
            client.logger.log("Некорректная команда клиента", INFO);
            cmd.clear();
            continue;
        }
    }
}

// Прием данных с сервера
void receive_data_from_server_loop(ClientSocket& client, KeyStorage& key_storage, char* buf, CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs)
{
    while (true)
    {
        // Читаем пакет данных
        int bytes_read = client.receive(buf, sizeof(Message));
        if (bytes_read <= 0)
        {
            client.logger.log("Ошибка чтения пакета данных", ERROR);
            break;
        }

        client.logger.log("Считано (байт): " + std::to_string(bytes_read), INFO);

        // Если был считан не весь пакет данных
        if(bytes_read != sizeof(Message)) 
        {
            client.logger.log("Неполные данные", ERROR);
            break;
        }

        Message msg;
        memcpy(&msg, buf, sizeof(Message));

        switch(msg.type) 
        {
            case 0x01: 
            {
                client.logger.log("Информационное сообщение", INFO);
                std::string info_msg(buf + PAYLOAD_OFFSET, msg.payload_size);
                client.logger.log(info_msg, INFO);
                break;
            }
            case 0x02:
            {
                client.logger.log("Команда от сервера", INFO);
                std::string control_msg(buf + PAYLOAD_OFFSET, msg.payload_size);
                if(control_msg == "STOP") 
                {
                    client.logger.log("Сервер остановлен", INFO);
                    client.~ClientSocket();
                    return;
                }
                else
                {
                    client.logger.log(control_msg, INFO);
                    break;
                }
            }
                
            case 0x03:
            {
                client.logger.log("Контейнер", INFO);
                process_key_container(client, key_storage, (void*)(buf + PAYLOAD_OFFSET), 
                                      msg.payload_size, session, funcs);
                break;
            }

            case 0x04:
            {
                client.logger.log("Ключ KGenKQPK", INFO);
                proccess_kgenqpk(client, key_storage, (void*)(buf + PAYLOAD_OFFSET), 
                             msg.payload_size, session, funcs);
                break;
            }

            case 0x05:
            {
                client.logger.log("Ключ QK", INFO);
                proccess_qk(client, key_storage, (void*)(buf + PAYLOAD_OFFSET), 
                             msg.payload_size);
                break;
            }

            default:
            {
                client.logger.log("Неизвестный тип сообщения", INFO);
                break;
            }
        }
    }
    exit(0);
}

void print_container_info(ClientSocket& client, Container& container)
{
    client.logger.log("label: " + bytes_to_hex_string(container.label, 8), INFO);
    client.logger.log("id QPK: " + bytes_to_hex_string(container.m, 6), INFO);
    client.logger.log("cs_cw: " + bytes_to_hex_string(container.cs_kw, 1), INFO);
    client.logger.log("id_base_key: " + bytes_to_hex_string(container.id_base_key, 16), INFO);
    client.logger.log("use_key_ctr: " + bytes_to_hex_string(container.use_key_ctr, 8), INFO);
    client.logger.log("dpu_id_initiator: " + bytes_to_hex_string(container.dpu_id_initiator, 16), INFO);
    client.logger.log("dpu_id_initiator_pair: " + bytes_to_hex_string(container.dpu_id_initiator_pair, 16), INFO);
    client.logger.log("dpu_id_sender: " + bytes_to_hex_string(container.dpu_id_sender, 16), INFO);
    client.logger.log("dpu_id_reciever: " + bytes_to_hex_string(container.dpu_id_receiver, 16), INFO);
    client.logger.log("kexp: " + bytes_to_hex_string(container.kexp, 48), INFO);
}

void process_key_container(ClientSocket& client, KeyStorage& key_storage, 
                           void* payload, uint32_t size, 
                           CK_SESSION_HANDLE session, 
                           CK_FUNCTION_LIST_PTR funcs) 
{
    CK_RV rv = CKR_OK;
    CK_BYTE rand_label[8] = {0x00, 0x00, 0x00, 0x00, 0x4B, 0x51, 0x50, 0x4B};
    CK_BYTE qrand_label[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x4B};

    // Обработка ключевого контейнера
    if(size != sizeof(Container)) 
    {
        client.logger.log("Некорректная длина контейнера!", INFO);
    }
    
    Container container;
    memcpy(&container, reinterpret_cast<Container*>(payload), sizeof(Container));
    print_container_info(client, container);

    // Тут нужно узнать какой ключ у контейнера
    if (memcmp(container.label, rand_label, 8) == 0)
    {
        KeyInfo rand_comp_key_info;
        CK_BYTE rand_comp[32] = {0};
        CK_BYTE rand_comp_id[16] = {0};
        CK_BYTE rand_comp_use_ctr[8] = {0};
        std::string rand_comp_str = {0};
        rv = component_extraction(session, funcs, &container, key_storage.get_key_value(KeyType::KQPK), 32, key_storage.get_key_ctr(KeyType::KQPK), 8, rand_comp);
        rand_comp_str = bytes_to_hex_string(rand_comp, 32);
        rv = C_GenerateRandom(session, rand_comp_id, 16); // Генерация id
        if (rv != CKR_OK) { client.logger.log("Ошибка генерации id компоненты Rand", ERROR); }
        memcpy(rand_comp_key_info.key_id, rand_comp_id, 16);
        memcpy(rand_comp_key_info.key_value, rand_comp, 32);
        memcpy(rand_comp_key_info.key_ctr, rand_comp_use_ctr, 8);
        client.logger.log("Rand: " + rand_comp_str, INFO);
        key_storage.add_key(KeyType::Rand, rand_comp_key_info);
    }
    else if (memcmp(container.label, qrand_label, 8) == 0)
    {
        KeyInfo qrand_comp_key_info;
        CK_BYTE qrand_comp[32] = {0};
        CK_BYTE qrand_comp_id[16] = {0};
        CK_BYTE qrand_comp_use_ctr[8] = {0};
        std::string qrand_comp_str = {0};
        rv = C_GenerateRandom(session, qrand_comp_id, 16); // Генерация id
        if (rv != CKR_OK) { client.logger.log("Ошибка генерации id компоненты QRand", ERROR); }
        memcpy(qrand_comp_key_info.key_id, qrand_comp_id, 16);
        memcpy(qrand_comp_key_info.key_value, qrand_comp, 32);
        memcpy(qrand_comp_key_info.key_ctr, qrand_comp_use_ctr, 8);
        component_extraction(session, funcs, &container, key_storage.get_key_value(KeyType::QK), 32, key_storage.get_key_ctr(KeyType::QK), 8, qrand_comp);
        qrand_comp_str = bytes_to_hex_string(qrand_comp, 32);
        client.logger.log("QRand: " + qrand_comp_str, INFO);
        key_storage.add_key(KeyType::QRand, qrand_comp_key_info);
    }

    // Если два контейнера, то можно генерировать набор ЦК
    if ((key_storage.get_key(KeyType::Rand) != nullptr) & (key_storage.get_key(KeyType::QRand) != nullptr))
    {
        CK_BYTE dpu_id_pair[32] = {0};
        memcpy(dpu_id_pair, container.dpu_id_initiator, 16);
        memcpy(dpu_id_pair + 16, container.dpu_id_initiator_pair, 16);
    
        // 30 целевых ключей по 256 байт
        const CK_ULONG key_len = 32;
        const CK_ULONG qpk_kit_count = 30;
        CK_BYTE qpk[qpk_kit_count][key_len] = {0};
        
        client.logger.log("Функция гибридизации начала работу", INFO);
        rv = kdfg(
            session, 
            funcs, 
            key_storage.get_key_value(KeyType::Rand),
            key_storage.get_key_value(KeyType::QRand),
            dpu_id_pair,
            32,
            container.m,
            6,
            qpk,
            qpk_kit_count
        );
        if (rv != CKR_OK) { client.logger.log("Ошибка функции гибридизации", ERROR); }
        for (CK_ULONG i = 0; i < qpk_kit_count; i++)
        {
            client.logger.log("QPK_" + std::to_string(i) + ": " + bytes_to_hex_string(qpk[i], key_len), INFO);
        }

        // Удаляем использованные компоненты
        key_storage.del_key(KeyType::Rand);
        key_storage.del_key(KeyType::QRand);
    }
}

void process_info_message(ClientSocket& client, const char* payload, uint32_t size) 
{
    // Обработка информационного сообщения
    std::string message(payload, size);
    client.logger.log(payload, INFO);
}

void proccess_kgenqpk(ClientSocket& client, KeyStorage& key_storage, void* payload, uint32_t size, 
                           CK_SESSION_HANDLE session, 
                           CK_FUNCTION_LIST_PTR funcs)
{
    CK_RV rv = CKR_OK;
    KeyInfo kgenqpk_key_info;
    client.logger.log("Ключ KGenQPK получен!", INFO);
    
    if(size != sizeof(KeyInfo)) 
    {
        client.logger.log("Некорретная длина структуры ключевой информации", INFO);
    }
    
    memcpy(&kgenqpk_key_info, reinterpret_cast<KeyInfo*>(payload), sizeof(KeyInfo));
    key_storage.add_key(KeyType::KGenQPK, kgenqpk_key_info);
    std::string kgenqpk_str = bytes_to_hex_string(key_storage.get_key_value(KeyType::KGenQPK), 32);
    std::string kgenqpk_id = bytes_to_hex_string(key_storage.get_key_id(KeyType::KGenQPK), 16);
    client.logger.log("KGenQPK: " + kgenqpk_str, INFO);
    client.logger.log("KGenQPK id: " + kgenqpk_id, INFO);

    // Создание ключей на основе базового
    KeyInfo kgenqpk_derive_key_info;
    CK_BYTE kgenqpk_derive[32] = {0};
    CK_BYTE kgenqpk_derive_id[16] = {0};
    CK_BYTE kgenqpk_derive_use_ctr[8] = {0};
    rv = C_GenerateRandom(session, kgenqpk_derive_id, 16); // Генерация id
    if (rv != CKR_OK) { client.logger.log("Ошибка генерации id производного ключа KGenQPK", ERROR); };

    KeyInfo kqpk_key_info;
    CK_BYTE kqpk[32] = {0};
    CK_BYTE kqpk_id[16] = {0};
    CK_BYTE kqpk_use_ctr[8] = {0};
    rv = C_GenerateRandom(session, kqpk_id, 16); // Генерация id
    if (rv != CKR_OK) { client.logger.log("Ошибка генерации id ключа KQPK", ERROR); }
    
    // На основе ключа генерации ключа защиты компоненты генерируем два ключа
    kdf1(session, funcs, key_storage.get_key_value(KeyType::KGenQPK), key_storage.get_key_ctr(KeyType::KGenQPK), kgenqpk_derive, kqpk);
    client.logger.log("Диверсификация ключей выполнена успешно", INFO);
    memcpy(kgenqpk_derive_key_info.key_id, kgenqpk_derive_id, 16);
    memcpy(kgenqpk_derive_key_info.key_value, kgenqpk_derive, 32);
    memcpy(kgenqpk_derive_key_info.key_ctr, kgenqpk_derive_use_ctr, 8);
    memcpy(kqpk_key_info.key_id, kqpk_id, 16);
    memcpy(kqpk_key_info.key_value, kqpk, 32);
    memcpy(kqpk_key_info.key_ctr, kqpk_use_ctr, 8);

    // Теперь нужно добавить ключи в ключевое хранилище
    key_storage.add_key(KeyType::KQPK, kqpk_key_info);

    std::string kqpk_str = bytes_to_hex_string(key_storage.get_key_value(KeyType::KQPK), 32);
    std::string kqpk_id_str = bytes_to_hex_string(key_storage.get_key_id(KeyType::KQPK), 16);
    client.logger.log("KQPK: " + kqpk_str, INFO);
    client.logger.log("KQPK id: " + kqpk_id_str, INFO);
}

void proccess_qk(ClientSocket& client, KeyStorage& key_storage, void* payload, uint32_t size)
{
    KeyInfo qk_key_info;
    client.logger.log("Ключ QK получен!", INFO);
    
    if(size != sizeof(KeyInfo)) 
    {
        client.logger.log("Некорретная длина структуры ключевой информации", INFO);
    }
    
    memcpy(&qk_key_info, reinterpret_cast<KeyInfo*>(payload), sizeof(KeyInfo));
    key_storage.add_key(KeyType::QK, qk_key_info);
    std::string qk_str = bytes_to_hex_string(key_storage.get_key_value(KeyType::QK), 32);
    std::string qk_id = bytes_to_hex_string(key_storage.get_key_id(KeyType::QK), 16);
    client.logger.log("QK: " + qk_str, INFO);
    client.logger.log("QK id: " + qk_id, INFO);

    // Теперь нужно добавить ключи в ключевое хранилище
    key_storage.add_key(KeyType::QK, qk_key_info);
}

int main()
{
    ClientSocket client;
    client.connect(IP, PORT);
    char buf[BUFFER_SIZE] = {0};

    // Инициализация библиотеки pkcs11
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList(); // получение списка функций

    KeyStorage key_storage;

    std::thread cmd_thread(input_cmd_loop, std::ref(client));
    std::thread receive_from_server_thread(receive_data_from_server_loop, std::ref(client), std::ref(key_storage), std::ref(buf), handle.session(), funcs);
    
    cmd_thread.join();
    receive_from_server_thread.join();

    // client.~ClientSocket();
}