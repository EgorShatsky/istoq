#ifndef CRYPTO_H
#define CRYPTO_H

#include <dlfcn.h>
#include <string>
#include <stdexcept>
#include <cstring>
#include "spbpkcs11.h"
#include "../include/utils.h"

#define KUZN_CMAC_SIZE 16
#define KEY_SIZE 32

class ServerSocket;
class ClientSocket;

class PKCS11Handle 
{
    CK_FUNCTION_LIST_PTR m_func_list = nullptr;
    CK_SESSION_HANDLE m_session = CK_INVALID_HANDLE;
    void* m_lib_handle = nullptr;
    bool m_initialized = false;
    bool m_session_open = false;
    bool m_logged_in = false;

    void check_rv(CK_RV rv, const std::string& message) 
    {
        if (rv != CKR_OK) 
        {
            throw std::runtime_error(message + " (Error code: " + std::to_string(rv) + ")");
        }
    }

public:
    PKCS11Handle(const char* lib_path, CK_SLOT_ID slotId = 0) 
    {
        // Загрузка библиотеки
        m_lib_handle = dlopen(lib_path, RTLD_LAZY);
        if (!m_lib_handle) 
        {
            throw std::runtime_error("Failed to load PKCS#11 library: " + std::string(dlerror()));
        }

        // Получение списка функций
        CK_C_GetFunctionList get_func_list = reinterpret_cast<CK_C_GetFunctionList>(dlsym(m_lib_handle, "C_GetFunctionList"));
        if (!get_func_list) 
        {
            dlclose(m_lib_handle);
            throw std::runtime_error("Failed to find C_GetFunctionList");
        }

        check_rv(get_func_list(&m_func_list), "C_GetFunctionList failed");

        // Инициализация библиотеки
        check_rv(m_func_list->C_Initialize(nullptr), "C_Initialize failed");
        m_initialized = true;

        // Открытие сессии
        check_rv(m_func_list->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &m_session), 
               "C_OpenSession failed");
        m_session_open = true;
    }

    void login(const char* pin, const char* pin2,  CK_USER_TYPE user_type = CKU_USER) 
    {
        CK_RV rv = m_func_list->C_Login(m_session, user_type, 
                                      reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(pin)), 
                                      strlen(pin));
        
        // Обработка случая, когда пользователь уже залогинен
        if (rv == CKR_PIN_INCORRECT)
        {
            rv = m_func_list->C_Login(m_session, user_type, 
                reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(pin2)), 
                strlen(pin2));
        }
        if (rv == CKR_USER_ALREADY_LOGGED_IN) 
        {
            m_logged_in = true;
            return;
        }

        check_rv(rv, "C_Login failed");
        m_logged_in = true;
    }

    CK_SESSION_HANDLE session() const { return m_session; }
    CK_FUNCTION_LIST_PTR functionList() const { return m_func_list; }

    ~PKCS11Handle() 
    {
        if (m_logged_in) 
        {
            m_func_list->C_Logout(m_session);
        }
        if (m_session_open) 
        {
            m_func_list->C_CloseSession(m_session);
        }
        if (m_initialized) 
        {
            m_func_list->C_Finalize(nullptr);
        }
        if (m_lib_handle) 
        {
            dlclose(m_lib_handle);
        }
    }

    // Удаляем копирование и присваивание
    PKCS11Handle(const PKCS11Handle&) = delete;
    PKCS11Handle& operator=(const PKCS11Handle&) = delete;
};

// Контейнер компоненты Rand|QRand
#pragma pack(push,1)
struct Container
{
    // Метаданные контейнера
    CK_BYTE label[8];                  // Тип используемого ключа QK/KQPK
    CK_BYTE m[6];                      // ID набора ЦК
    CK_BYTE cs_kw[1];                  // используемый криптонабор 0 - кузнечик, 1 - магма
    CK_BYTE id_base_key[16];           // ID используемого ключа
    CK_BYTE use_key_ctr[8];            // Счетчик использования ключа
    CK_BYTE dpu_id_initiator[16];      // ID ДПУ, который сделал запрос на получение набора ЦК
    CK_BYTE dpu_id_initiator_pair[16]; // ID ДПУ, который в паре с ДПУ, который сделал запрос на получение набора ЦК
    CK_BYTE dpu_id_sender[16];         // ID ДПУ, на котором был сформирован контейнер
    CK_BYTE dpu_id_receiver[16];       // ID ДПУ для, которого сформирован контейнер

    // Экспортное представление компонеты
    CK_BYTE kexp[48];                   
};
#pragma pack(pop)

// Формирование экспортного представления KEXP Kuznechik
CK_RV kexp15_kuzn(
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs,
    CK_BYTE_PTR enc_key_value,      // Значение ключа для шифрования контейнера
    CK_ULONG enc_key_size,          // Длина ключа для шифрования контейнера
    CK_BYTE_PTR packable_key_value, // Значение компоненты для упаковки
    CK_ULONG packable_key_size,     // Длина компоненты для упаковки
    CK_BYTE_PTR key_ctr,            // Счетчик использования ключа
    CK_ULONG key_ctr_size,          // Размер счетчика использования ключа (8 байт)
    CK_BYTE_PTR kexp_out_value,     // Выходное значение экспортного представления KEXP
    CK_ULONG_PTR kexp_out_size      // Длина KEXP 48 байт
);

// Формирование экспортного представления KEXP Magma
CK_RV kexp15_magma(
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs,
    CK_BYTE_PTR enc_key_value,      // Значение ключа для шифрования контейнера
    CK_ULONG enc_key_size,          // Длина ключа для шифрования контейнера
    CK_BYTE_PTR packable_key_value, // Значение компоненты для упаковки
    CK_ULONG packable_key_size,     // Длина компоненты для упаковки
    CK_BYTE_PTR key_ctr,            // Счетчик использования ключа
    CK_ULONG key_ctr_size,          // Размер счетчика использования ключа (4 байта)
    CK_BYTE_PTR kexp_out_value,     // Выходное значение экспортного представления KEXP
    CK_ULONG_PTR kexp_out_size      // Длина KEXP 40 байт
);

// Извлечение ключа из контейнера
CK_RV component_extraction(
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs,
    Container* container,         // Контейнер, в котором находится компонента
    CK_BYTE_PTR extraction_key,   // Ключ для расшифрования экспортного представления
    CK_ULONG extraction_key_size, // Длина ключа
    CK_BYTE_PTR key_ctr,          // Счетчик использования ключей
    CK_ULONG key_ctr_size,        // Длина счетчика
    CK_BYTE_PTR comp              // Извлеченная компонента
);

// Функция формирования контейнера с KEXP
void container_form(
    Container* container,   
    CK_BYTE_PTR label, CK_ULONG label_size,
    CK_BYTE_PTR m, CK_ULONG m_size,
    CK_BYTE_PTR cs_kw, CK_ULONG cs_ks_size,
    CK_BYTE_PTR key_id, CK_ULONG key_id_size,
    CK_BYTE_PTR key_ctr, CK_ULONG key_ctr_size,
    CK_BYTE_PTR dpu_id_initiator, CK_ULONG dpu_id_initiator_size,
    CK_BYTE_PTR dpu_id_initiator_pair, CK_ULONG dpu_id_initiator_pair_size,
    CK_BYTE_PTR dpu_id_sender, CK_ULONG dpu_id_sender_size,
    CK_BYTE_PTR dpu_id_receiver, CK_ULONG dpu_id_receiver_size,
    CK_BYTE_PTR kexp, CK_ULONG kexp_size
);

// Функция гибридизации
CK_RV kdfg(
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs, 
    CK_BYTE_PTR rand_comp,     // Компонента Rand
    CK_BYTE_PTR qrand_comp,    // Компонента QRand
    CK_BYTE_PTR id_dpu_pair,   // ID ДПУ клиентов NodeA||NodeB
    CK_ULONG id_dpu_pair_size, // 32 байта
    CK_BYTE_PTR id_qpk,        // ID набора ЦК
    CK_ULONG id_qpk_size,      // Длина ID набора (6 байт)
    CK_BYTE qpk[][32],         // Набор ЦК
    CK_ULONG qpk_kit_count     // Количество ключей в наборе ЦК
);

CK_RV kdf1(
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs, 
    CK_BYTE_PTR kgenqpk_base,             // Ключ KGenQPK из которого делается KQPK и KGenQPK + 1
    CK_BYTE_PTR kgenqpk_base_use_key_ctr, // Счетчик использования KGenQPK
    CK_BYTE_PTR kgenqpk_derive,           // Указатель на массив для ключа KGenQPK + 1
    CK_BYTE_PTR kqpk                      // Ключ KQPK
);

CK_RV key_gen_256(
    CK_SESSION_HANDLE session, 
    CK_FUNCTION_LIST_PTR funcs,
    CK_BYTE_PTR key                       // Указатель на массив ключа                                       
);
                            
#endif // CRYPTO_H