#include <iostream>
#include <vector>
#include <cstdint>
#include "../include/server.h"
#include "../include/client.h"
#include "../include/crypto.h"

CK_RV kexp15_kuzn(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs,
    CK_BYTE_PTR enc_key_value, CK_ULONG enc_key_size,
    CK_BYTE_PTR packable_key_value, CK_ULONG packable_key_size,
    CK_BYTE_PTR key_ctr, CK_ULONG key_ctr_size,
    CK_BYTE_PTR kexp_out_value, CK_ULONG_PTR kexp_out_size)
{
    if ((enc_key_size | packable_key_size) != 32)
        return -1;

    if (*kexp_out_size != 48)
        return -1;

    CK_RV rv = CKR_OK;
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;

    // Механизм для KExp15 "Kuznechik"
    // Передаем в механизм вектор инициализации (IV), который является счетчиком
    CK_MECHANISM kexp_mechanism = { CKM_KUZNECHIK_KEXP_15_WRAP, key_ctr, key_ctr_size };

    CK_BYTE twin_enc_key_val[64] = {0};
    memcpy(twin_enc_key_val, enc_key_value, 32);
    memcpy(twin_enc_key_val + 32, enc_key_value, 32);

    // Хэндл ключа шифрования контейнера
    CK_OBJECT_HANDLE enc_key_handle = CK_INVALID_HANDLE;

    // Хэндл компоненты (упаковываемый ключ)
    CK_OBJECT_HANDLE packable_key_handle = CK_INVALID_HANDLE;

    // Параметры ключа
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE twin_type = CKK_KUZNECHIK_TWIN_KEY;
    CK_KEY_TYPE key_type = CKK_KUZNECHIK; 

    // Шаблон ключа шифрования контейнера
    CK_ATTRIBUTE enc_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &twin_type, sizeof(twin_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_WRAP, &b_true, sizeof(b_true)},
        {CKA_UNWRAP, &b_true, sizeof(b_true)},
        {CKA_VALUE, twin_enc_key_val, enc_key_size*2}
    };

    // Шаблон packable key (компоненты)
    CK_ATTRIBUTE packable_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_ENCRYPT, &b_true, sizeof(b_true)},
        {CKA_DECRYPT, &b_true, sizeof(b_true)},
        {CKA_VALUE, packable_key_value, packable_key_size}
    };

    // Создание объекта ключа шифрования контейнера
    rv = funcs->C_CreateObject(session, enc_key_template, sizeof(enc_key_template) / sizeof(CK_ATTRIBUTE), &enc_key_handle);

    // Создание объекта компоненты
    rv = funcs->C_CreateObject(session, packable_key_template, sizeof(packable_key_template) / sizeof(CK_ATTRIBUTE), &packable_key_handle);

    // Оборачивание в контейнер
    rv = funcs->C_WrapKey(session, &kexp_mechanism, enc_key_handle, packable_key_handle, kexp_out_value, kexp_out_size);

    increment_ctr(key_ctr, 8);
    return rv;
}

CK_RV component_extraction(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs, 
    Container *container, CK_BYTE_PTR extraction_key, CK_ULONG extraction_key_size,
    CK_BYTE_PTR key_ctr, CK_ULONG key_ctr_size, CK_BYTE_PTR component)
{
    CK_RV rv = CKR_OK;
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;

    // Извлечь KEKP из контейнера
    CK_BYTE kexp[48];
    memcpy(kexp, container->kexp, 48);

    CK_BYTE twin_enc_key_val[64] = {0};
    memcpy(twin_enc_key_val, extraction_key, 32);
    memcpy(twin_enc_key_val + 32, extraction_key, 32);

    CK_MECHANISM kexp_mechanism = { CKM_KUZNECHIK_KEXP_15_WRAP, key_ctr, key_ctr_size};

    // Хэндл ключа расшифрования контейнера
    CK_OBJECT_HANDLE extraction_key_handle = CK_INVALID_HANDLE;

    // Хэндл извлекаемой компоненты (извлекаемый ключ)
    CK_OBJECT_HANDLE extracted_key_handle = CK_INVALID_HANDLE;

    // Параметры ключа
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE twin_type = CKK_KUZNECHIK_TWIN_KEY;
    CK_KEY_TYPE key_type = CKK_KUZNECHIK; 

    // Шаблон ключа извлечения содержимого контейнера
    CK_ATTRIBUTE extraction_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &twin_type, sizeof(twin_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_WRAP, &b_true, sizeof(b_true)},
        {CKA_UNWRAP, &b_true, sizeof(b_true)},
        {CKA_VALUE, twin_enc_key_val, extraction_key_size*2}
    };

    // Шаблон извлеченной компоненты
    CK_ATTRIBUTE extracted_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_EXTRACTABLE, &b_true, sizeof(b_true)},
        {CKA_SENSITIVE, &b_false, sizeof(b_false)}
    };

    // Создание объекта ключа извлечения содержимого контейнера
    rv = funcs->C_CreateObject(session, extraction_key_template, sizeof(extraction_key_template) / sizeof(CK_ATTRIBUTE), &extraction_key_handle);
   
    // Извлечение
    rv = funcs->C_UnwrapKey(session, &kexp_mechanism, extraction_key_handle, kexp, 48, extracted_key_template, sizeof(extracted_key_template) / sizeof(CK_ATTRIBUTE), &extracted_key_handle);
   
    // Нужно извлечь значение в component
    CK_ATTRIBUTE key_attr = {CKA_VALUE, component, 32};
    rv = funcs->C_GetAttributeValue(session, extracted_key_handle, &key_attr, 1);

    increment_ctr(key_ctr, 8);

    funcs->C_DestroyObject(session, extracted_key_handle);
    funcs->C_DestroyObject(session, extraction_key_handle);

    return rv;
}

CK_RV kexp15_magma(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs,
    CK_BYTE_PTR enc_key_value, CK_ULONG enc_key_size,
    CK_BYTE_PTR packable_key_value, CK_ULONG packable_key_size,
    CK_BYTE_PTR key_ctr, CK_ULONG key_ctr_size,
    CK_BYTE_PTR kexp_out_value, CK_ULONG_PTR kexp_out_size)
{
    CK_RV rv = CKR_OK;
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;

    // Механизм для KExp15 "Magma"
    // Передаем в механизм вектор инициализации (IV), который является счетчиком
    CK_MECHANISM kexp_mechanism = { CKM_MAGMA_KEXP_15_WRAP, key_ctr, key_ctr_size };

    // Хэндл ключа шифрования контейнера
    CK_OBJECT_HANDLE enc_key_handle = CK_INVALID_HANDLE;

    // Хэндл компоненты (упаковываемый ключ)
    CK_OBJECT_HANDLE packable_key_handle = CK_INVALID_HANDLE;

    // Параметры ключа
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_MAGMA; 

    // Шаблон ключа шифрования контейнера
    CK_ATTRIBUTE enc_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_WRAP, &b_true, sizeof(b_true)},
        {CKA_UNWRAP, &b_true, sizeof(b_true)},
        {CKA_VALUE, enc_key_value, enc_key_size}
    };

    // Шаблон packable key (компоненты)
    CK_ATTRIBUTE packable_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_ENCRYPT, &b_true, sizeof(b_true)},
        {CKA_DECRYPT, &b_true, sizeof(b_true)},
        {CKA_VALUE, packable_key_value, packable_key_size}
    };

    // Создание объекта ключа шифрования контейнера
    rv = funcs->C_CreateObject(session, enc_key_template, sizeof(enc_key_template) / sizeof(CK_ATTRIBUTE), &enc_key_handle);

    // Создание объекта компоненты
    rv = funcs->C_CreateObject(session, packable_key_template, sizeof(packable_key_template) / sizeof(CK_ATTRIBUTE), &packable_key_handle);

    // Оборачивание в контейнер
    rv = funcs->C_WrapKey(session, &kexp_mechanism, enc_key_handle, packable_key_handle, kexp_out_value, kexp_out_size);

    return rv;
}

void container_form(Container *container, CK_BYTE_PTR label, CK_ULONG label_size,
    CK_BYTE_PTR m, CK_ULONG m_size, CK_BYTE_PTR cs_kw, CK_ULONG cs_ks_size,
    CK_BYTE_PTR key_id, CK_ULONG key_id_size, CK_BYTE_PTR key_ctr, CK_ULONG key_ctr_size, 
    CK_BYTE_PTR dpu_id_initiator, CK_ULONG dpu_id_initiator_size, CK_BYTE_PTR dpu_id_initiator_pair, 
    CK_ULONG dpu_id_initiator_pair_size, CK_BYTE_PTR dpu_id_sender, CK_ULONG dpu_id_sender_size,
    CK_BYTE_PTR dpu_id_receiver, CK_ULONG dpu_id_receiver_size, CK_BYTE_PTR kexp, CK_ULONG kexp_size)
{
    memcpy(container->label, label, label_size);
    memcpy(container->m, m, m_size);
    memcpy(container->cs_kw, cs_kw, cs_ks_size);
    memcpy(container->id_base_key, key_id, key_id_size);
    memcpy(container->use_key_ctr, key_ctr, key_ctr_size);
    memcpy(container->dpu_id_initiator, dpu_id_initiator, dpu_id_initiator_size);
    memcpy(container->dpu_id_initiator_pair, dpu_id_initiator_pair, dpu_id_initiator_pair_size);
    memcpy(container->dpu_id_sender, dpu_id_sender, dpu_id_sender_size);
    memcpy(container->dpu_id_receiver, dpu_id_receiver, dpu_id_receiver_size);
    memcpy(container->kexp, kexp, kexp_size);
}

CK_RV kdfg(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs, 
    CK_BYTE_PTR rand_comp, CK_BYTE_PTR qrand_comp, CK_BYTE_PTR id_dpu_pair, 
    CK_ULONG id_dpu_pair_size, CK_BYTE_PTR id_qpk, CK_ULONG id_qpk_size, 
    CK_BYTE qpk[][32], CK_ULONG qpk_kit_count)
{
     if (rand_comp == nullptr)
        return -1;
    
    if (qrand_comp == nullptr)
        return -1;

    if (id_dpu_pair == nullptr)
        return -1;

    if (id_qpk == nullptr)
        return -1;

    CK_RV rv = CKR_OK;
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;
    const CK_ULONG label_size = 8;
    CK_BYTE label[label_size] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x50, 0x4B};

    // Параметры для временного ключа (на нем вычисляется CMAC)
    CK_MECHANISM mechanism = { CKM_KUZNECHIK_MAC, NULL_PTR, 0 };
    CK_KEY_TYPE key_type = CKK_KUZNECHIK;
    CK_OBJECT_CLASS key_object = CKO_SECRET_KEY;

    // Вычисление промежуточного ключа (Rand XOR QRand)
    CK_OBJECT_HANDLE tmp_key_handle = CK_INVALID_HANDLE;
    const CK_ULONG tmp_key_size = 32;
    CK_BYTE tmp_key[tmp_key_size];
    for (CK_ULONG i = 0; i < tmp_key_size; i++)
    {
        tmp_key[i] = rand_comp[i]^qrand_comp[i];
    }

    // Шаблон промежуточного ключа
    CK_ATTRIBUTE tmp_key_template[] = {
        {CKA_CLASS, &key_object, sizeof(key_object)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_true)},
        {CKA_SIGN, &b_true, sizeof(b_true)},
        {CKA_VERIFY, &b_true, sizeof(b_true)},
        {CKA_VALUE, tmp_key, tmp_key_size},
    };

    // Создание объекта промежуточного ключа 
    rv = funcs->C_CreateObject(session, tmp_key_template, sizeof(tmp_key_template) / sizeof(CK_ATTRIBUTE), &tmp_key_handle);

    // m - идентификатор формируемого набора ЦК (6 байт)
    // Сi - номер ключа из набора ЦК (по какому идет итерация) (4 байта)
    // P (label) - метка назначения (8 байт)
    // U - ID пары ДПУ (32 байта)
    // L - Длина набора ЦК (4 байта)
    // Итого 6 + 4 + 8 + 32 + 4 = 54 байта

    const CK_ULONG sign_data_size = 54;  
    CK_BYTE sign_data[sign_data_size];

    memcpy(sign_data, id_qpk, id_qpk_size);
    memcpy(sign_data + id_qpk_size + 4, label, label_size);
    memcpy(sign_data + id_qpk_size + 4 + label_size, id_dpu_pair, id_dpu_pair_size);

    // Конвертируем количество ключей набора в массив
    CK_BYTE qpk_ctr[4] = {0};
    convert_ulong_to_bytes(qpk_kit_count, 4, qpk_ctr);

    memcpy(sign_data + id_qpk_size + 4 + label_size + id_dpu_pair_size, qpk_ctr, 4);

    CK_BYTE cmac_iter_ctr[4] = {0};

    // Для одного ключа набора ЦК нужно две итерации CMAC
    // Так как длина выхода CMAC - 16 байт, а ключ ЦК 32 байта
    for (CK_ULONG i = 0; i < qpk_kit_count * 2; i++)
    {
        CK_ULONG cmac_size = 16;
        const CK_ULONG tmp_cmac_size = 16;
        CK_BYTE tmp_cmac[tmp_cmac_size]; // Буфер CMAC

        const CK_ULONG buf_qpk_size = 32;
        CK_BYTE buf_qpk[buf_qpk_size]; // Буфер ЦК

        convert_ulong_to_bytes(i, 4, cmac_iter_ctr);
        memcpy(sign_data + id_qpk_size, cmac_iter_ctr, 4);
  
        rv = funcs->C_SignInit(session, &mechanism, tmp_key_handle);

        rv = funcs->C_Sign(session, sign_data, sizeof(sign_data) / sizeof(CK_BYTE), tmp_cmac, &cmac_size);

        // Если i четное, то копируем в первую часть
        if (i%2 == 0)
        {
            memcpy(buf_qpk, tmp_cmac, 16);
        }

        // Если i нечетное, то копируем во вторую часть
        if (i%2 != 0)
        {
            memcpy(buf_qpk + 16, tmp_cmac, 16);
             
            // Добавить в набор ЦК
            memcpy(qpk[i/2], buf_qpk, 32);
 
            // Обнуляем буферы
            memset(buf_qpk, 0, 32);
            memset(tmp_cmac, 0, 16);
        }
    }

    return rv;
}

// Функция обновления компоненты для ключа KQPK
CK_RV kdf1(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs, 
          CK_BYTE_PTR kgenqpk_base, CK_BYTE_PTR kgenqpk_base_use_key_ctr,  
          CK_BYTE_PTR kgenqpk_derive, CK_BYTE_PTR kqpk)
{
    if (kgenqpk_base == nullptr)
        return -1;
    
    if (kgenqpk_base_use_key_ctr == nullptr)
        return -1;

    if (kgenqpk_derive == nullptr)
        return -1;

    if (kqpk == nullptr)
        return -1;

    CK_RV rv = CKR_OK;
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;
    CK_KEY_TYPE key_type = CKK_MAGMA;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;

    // Хэндл базового ключа KGenQPK
    CK_OBJECT_HANDLE kgenqpk_base_key_handle = CK_INVALID_HANDLE;

    // Хэндл KGenQPK + 1
    CK_OBJECT_HANDLE kgenqpk_key_handle = CK_INVALID_HANDLE;

    // Хэндл ключа защиты компоненты
    CK_OBJECT_HANDLE kqpk_key_handle = CK_INVALID_HANDLE;

    // label - назначение
    CK_BYTE label_kgenqpk[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                0x00, 0x4b, 0x47, 0x65, 0x6e, 0x51, 0x50, 0x4b }; // KGenQPK

    CK_BYTE label_kqpk[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                             0x00, 0x00, 0x00, 0x00, 0x4b, 0x51, 0x50, 0x4b }; // KQPK

    // Параметры KDF для KGenQPK ключа
    CK_KDF_TREE_GOST_PARAMS kqpkgen_key_params = {
        sizeof(label_kgenqpk), label_kgenqpk, 
        sizeof(kgenqpk_base_use_key_ctr), kgenqpk_base_use_key_ctr, // Счетчик использования
        1, 64, 32                                                   // ulR, ulL, iloffset
    };

    // Параметры KDF для KQPK ключа
    CK_KDF_TREE_GOST_PARAMS kqpk_key_params = {
        sizeof(label_kqpk), label_kqpk, 
        sizeof(kgenqpk_base_use_key_ctr), kgenqpk_base_use_key_ctr,            
        1, 64, 32
    };

    // Шаблон базовый KGenQPK
    CK_ATTRIBUTE kqpk_base_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_DERIVE, &b_true, sizeof(b_true)},
        {CKA_VALUE, kgenqpk_base, 32},
    };

    // Создание объекта базового ключа KGenQPK
    rv = funcs->C_CreateObject(session, kqpk_base_key_template, sizeof(kqpk_base_key_template) / sizeof(CK_ATTRIBUTE), &kgenqpk_base_key_handle);

    // Шаблон KGenQPK
    CK_ATTRIBUTE kqpk_gen_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_false, sizeof(b_false)},
        {CKA_DERIVE, &b_true, sizeof(b_true)},
        {CKA_EXTRACTABLE, &b_true, sizeof(b_true)}
    };

    // Шаблон KQPK
    CK_ATTRIBUTE kqpk_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_false, sizeof(b_false)},
        {CKA_DERIVE, &b_true, sizeof(b_true)},
        {CKA_EXTRACTABLE, &b_true, sizeof(b_true)}
    };

    // Вызовы DeriveKey с разными параметрами
    CK_MECHANISM kgenqpk_mech = {CKM_KDF_TREE_GOSTR3411_2012_256, &kqpkgen_key_params, sizeof(kqpkgen_key_params)};
    CK_MECHANISM kqpk_mech = {CKM_KDF_TREE_GOSTR3411_2012_256, &kqpk_key_params, sizeof(kqpk_key_params)};

    // Генерация KGenQPK ключа
    rv = funcs->C_DeriveKey(
        session,
        &kgenqpk_mech,
        kgenqpk_base_key_handle, // базовый handle
        kqpk_gen_template,
        sizeof(kqpk_gen_template)/sizeof(kqpk_gen_template[0]),
        &kgenqpk_key_handle // новый handle
    );

    // Генерация KQPK ключа
    rv = funcs->C_DeriveKey(
        session,
        &kqpk_mech,
        kgenqpk_base_key_handle,
        kqpk_template,
        sizeof(kqpk_template)/sizeof(kqpk_template[0]),
        &kqpk_key_handle
    );

    // Извлечение KGenQPK
    CK_ATTRIBUTE kgenqpk_key_attr = {CKA_VALUE,  kgenqpk_derive, 32};
    rv = funcs->C_GetAttributeValue(session, kgenqpk_key_handle, &kgenqpk_key_attr, 1);

    // Извлечение KQPK
    CK_ATTRIBUTE kqpk_key_attr = {CKA_VALUE,  kqpk, 32};
    rv = funcs->C_GetAttributeValue(session, kqpk_key_handle, &kqpk_key_attr, 1);

    // Увеличиваем счетчик использования ключа 
    increment_ctr(kgenqpk_base_use_key_ctr, 8);

    return rv;
}

// Функция генерации мастер-ключа длиной 32 байта
CK_RV key_gen_256(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR funcs, CK_BYTE_PTR key) 
{
    if (funcs == nullptr)
        return -1;
    if (key == nullptr)
        return -1;

    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;
    CK_OBJECT_HANDLE master_key;
    CK_MECHANISM mech = {CKM_MAGMA_KEY_GEN, nullptr, 0};
    CK_KEY_TYPE key_type = CKK_MAGMA;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;

    // Шаблон параметров для создания ключа
    CK_ATTRIBUTE template_[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_false, sizeof(b_false)},
        {CKA_DERIVE, &b_true, sizeof(b_true)}, // на базе ключа можно создавать производные
        {CKA_EXTRACTABLE, &b_true, sizeof(b_true)}
    };

    // Создание ключа
    CK_RV rv = funcs->C_GenerateKey(
        session,
        &mech,
        template_,
        sizeof(template_)/sizeof(CK_ATTRIBUTE),
        &master_key
    );

    // Извлечение значения ключа
    CK_ATTRIBUTE key_attr = {CKA_VALUE, key, 32};
    rv = funcs->C_GetAttributeValue(session, master_key, &key_attr, 1);

    return rv;
}