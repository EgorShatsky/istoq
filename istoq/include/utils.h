#ifndef UTILS_H
#define UTILS_H

#include <cinttypes>
#include <unordered_map>
#include "spbpkcs11.h"

#define PAYLOAD_OFFSET sizeof(uint8_t) + sizeof(uint32_t)

#pragma pack(push, 1)
struct Message {
    uint8_t type;                                                     // Тип сообщения: 0x01 - INFO, 0x02 - Command (STOP), 0x03 - Container, 0x04 - Key
    uint32_t payload_size;                                            // Размер данных после заголовка
    uint8_t payload[1024 - (sizeof(uint8_t) + sizeof(payload_size))]; // Полезная нагрузка
};
#pragma pack(pop)

#pragma pack(push,1)
struct KeyInfo{
    CK_BYTE key_value[32];
    CK_BYTE key_id[16];
    CK_BYTE key_ctr[8];
};
#pragma pack(pop)

// Хранилище ключей
enum class KeyType { Rand, QRand, QK, KGenQPK, KQPK }; // Тип ключевой информации

class KeyStorage 
{
    std::unordered_map<KeyType, KeyInfo> keys;
        
public:
    void add_key(KeyType type, const KeyInfo& key) 
    {
        keys[type] = key;
    }

    void del_key(KeyType type)
    {
        keys.erase(type);
    }
    
    KeyInfo* get_key(KeyType type) 
    {
        if (auto type_it = keys.find(type); type_it != keys.end()) 
        {
            return &type_it->second;
        }
        return nullptr;
    }

    CK_BYTE* get_key_value(KeyType type) 
    {
        if (auto it = keys.find(type); it != keys.end()) 
        {
            return it->second.key_value;
        }
        return nullptr;
    }

    CK_BYTE* get_key_id(KeyType type) 
    {
        if (auto it = keys.find(type); it != keys.end()) 
        {
            return it->second.key_id;
        }
        return nullptr;
    }

    CK_BYTE* get_key_ctr(KeyType type) 
    {
        if (auto it = keys.find(type); it != keys.end()) 
        {
            return it->second.key_ctr;
        }
        return nullptr;
    }
};

void convert_ulong_to_bytes(CK_ULONG num, CK_ULONG num_size, CK_BYTE_PTR array);
CK_ULONG convert_bytes_to_ulong(const CK_BYTE_PTR array, CK_ULONG num_size);
std::string bytes_to_hex_string(const CK_BYTE_PTR key, CK_ULONG key_size);       // Преобразование массива CK_BYTE в hex представление
void increment_ctr(CK_BYTE_PTR ctr, CK_ULONG ctr_size);                          // Увеличение счетчика CK_BYTE на единицу 

#endif // UTILS_H