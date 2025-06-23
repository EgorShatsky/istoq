#include <string>
#include <gtest/gtest.h>
#include "spbpkcs11.h"
#include "../include/utils.h"
#include "../include/crypto.h"

TEST(UtilsTest, convert_ulong_to_bytes)
{
    CK_BYTE etalon[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    CK_BYTE array[10] = {0};
    CK_ULONG num = 1;
    CK_ULONG num_size = 10;
    convert_ulong_to_bytes(num, num_size, array);
    EXPECT_EQ(memcmp(array, etalon, 10), 0);
}

TEST(UtilsTest, convert_ulong_to_bytes_invalid_cases)
{
    // Нулевой размер буфера
    CK_ULONG num = 1;
    CK_ULONG num_size = 0;
    CK_BYTE array[1] = {0xFF};
    convert_ulong_to_bytes(num, num_size, array);

    // Буфер не должен измениться
    EXPECT_EQ(array[0], 0xFF);

    // Переполнение буфера
    num = 0x100; // 256
    num_size = 1;
    convert_ulong_to_bytes(num, num_size, array);

    // Должен записаться только младший байт
    EXPECT_EQ(array[0], 0x00); 

    // Нулевой указатель буфера
    EXPECT_DEATH(convert_ulong_to_bytes(1, 1, nullptr), ".*");
}

TEST(UtilsTest, convert_bytes_to_ulong)
{
    CK_BYTE array[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    CK_ULONG etalon = 1;
    CK_ULONG array_size = 10;
    CK_ULONG result = convert_bytes_to_ulong(array, array_size);
    EXPECT_EQ(result, etalon);
}

TEST(UtilsTest, convert_bytes_to_ulong_invalid_cases)
{
    // Нулевой размер массива
    CK_BYTE array[1] = {0x01};
    CK_ULONG result = convert_bytes_to_ulong(array, 0);
    EXPECT_EQ(result, 0);

    // Нулевой указатель
    EXPECT_DEATH(convert_bytes_to_ulong(nullptr, 1), ".*");
}

TEST(UtilsTest, bytes_to_hex_string)
{
    CK_BYTE array[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    CK_ULONG array_size = 10;
    std::string etalon = "00 00 00 00 00 00 00 00 00 01";
    std::string result = bytes_to_hex_string(array, array_size); 
    int comp = etalon.compare(result);
    EXPECT_EQ(comp, 0);
}

TEST(UtilsTest, bytes_to_hex_string_invalid_cases)
{
    // Нулевой размер массива
    CK_BYTE array[1] = {0x01};
    std::string result = bytes_to_hex_string(array, 0);
    EXPECT_TRUE(result.empty());

    // Нулевой указатель
    EXPECT_DEATH(bytes_to_hex_string(nullptr, 1), ".*");
}

TEST(UtilsTest, increment_ctr)
{
    CK_BYTE ctr[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    CK_BYTE etalon[10] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    CK_ULONG ctr_size = 10;
    increment_ctr(ctr, ctr_size);
    EXPECT_EQ(memcmp(ctr, etalon, 10), 0);           
}

TEST(UtilsTest, increment_ctr_invalid_cases)
{
    // Переполнение счетчика
    CK_BYTE ctr[2] = {0xFF, 0xFF};
    CK_BYTE etalon[2] = {0x00, 0x00};
    increment_ctr(ctr, 2);
    EXPECT_EQ(memcmp(ctr, etalon, 2), 0);

    // Нулевой размер
    CK_BYTE ctr2[1] = {0xFF};
    increment_ctr(ctr2, 0);
    EXPECT_EQ(ctr2[0], 0xFF); // Не должен измениться

    // Нулевой указатель
    EXPECT_DEATH(increment_ctr(nullptr, 1), ".*");
}

TEST(CryptoTest, kexp15_kuzn)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();

    CK_BYTE etalon[48] = {0x20, 0xD7, 0xF1, 0x31, 0xDB, 0x9E, 0xF3, 0xD7, 
                          0xF9, 0x0D, 0xE7, 0x18, 0x20, 0x00, 0x25, 0x0A, 
                          0x12, 0xD8, 0x69, 0xE7, 0xD2, 0x30, 0xA2, 0x5C, 
                          0x86, 0x4B, 0xDF, 0x9A, 0x05, 0x12, 0x0D, 0xEC, 
                          0x26, 0x3B, 0xFB, 0xDD, 0xD8, 0xE7, 0x43, 0xF1, 
                          0x76, 0x30, 0x14, 0x61, 0x79, 0x1A, 0x41, 0x2D};

    CK_BYTE qrand_comp[32] = { 0x60, 0xD5, 0x5B, 0x03, 0x58, 0x6C, 0xF0, 0x13, 
                               0x49, 0x06, 0x75, 0xA1, 0x74, 0x0E, 0x81, 0xD9, 
                               0xB0, 0x51, 0xBE, 0x05, 0xB0, 0x62, 0x3F, 0xA2, 
                               0x0E, 0x8D, 0x5B, 0x13, 0xB2, 0xD3, 0x88, 0xA7 };

    CK_BYTE qk[32] = { 0xC0, 0xC3, 0x19, 0x46, 0xBD, 0x44, 0x74, 0x39, 
                       0xAE, 0x8C, 0x0A, 0x7B, 0x47, 0x7A, 0xE6, 0x99, 
                       0xEB, 0xE4, 0x65, 0x33, 0x30, 0x41, 0x2C, 0x5A, 
                       0xB7, 0x0D, 0xEB, 0x4B, 0xD6, 0x58, 0x42, 0x3D };

    CK_BYTE qrand_kexp[48] = {0};
    CK_ULONG kexp_size = 48;
    CK_BYTE key_ctr[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
                 
    kexp15_kuzn(
        handle.session(), 
        funcs, 
        qk, 
        32, 
        qrand_comp,
        32, 
        key_ctr, 
        8, 
        qrand_kexp,
        &kexp_size
    );

    EXPECT_EQ(memcmp(qrand_kexp, etalon, 48), 0);
}

TEST(CryptoTest, kexp15_kuzn_invalid_cases)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    
    CK_BYTE qk[32] = { 0xC0, 0xC3, 0x19, 0x46, 0xBD, 0x44, 0x74, 0x39, 
                       0xAE, 0x8C, 0x0A, 0x7B, 0x47, 0x7A, 0xE6, 0x99, 
                       0xEB, 0xE4, 0x65, 0x33, 0x30, 0x41, 0x2C, 0x5A, 
                       0xB7, 0x0D, 0xEB, 0x4B, 0xD6, 0x58, 0x42, 0x3D };

    CK_BYTE qrand_comp[32] = { 0x60, 0xD5, 0x5B, 0x03, 0x58, 0x6C, 0xF0, 0x13, 
                               0x49, 0x06, 0x75, 0xA1, 0x74, 0x0E, 0x81, 0xD9, 
                               0xB0, 0x51, 0xBE, 0x05, 0xB0, 0x62, 0x3F, 0xA2, 
                               0x0E, 0x8D, 0x5B, 0x13, 0xB2, 0xD3, 0x88, 0xA7 };

    CK_BYTE key_ctr[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    CK_BYTE qrand_kexp[48] = {0};
    CK_ULONG kexp_size = 48;

    // Неверный размер ключа
    EXPECT_EQ(kexp15_kuzn(handle.session(), handle.functionList(), qk, 31, qrand_comp, 32, key_ctr, 8, qrand_kexp, &kexp_size), -1);

    // Неверный размер kexp
    kexp_size = 18;
    EXPECT_EQ(kexp15_kuzn(handle.session(), handle.functionList(), qk, 32, qrand_comp, 32, key_ctr, 8, qrand_kexp, &kexp_size), -1);
}

TEST(CryptoTest, kdf1)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    CK_BYTE key_ctr[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    CK_BYTE base_key[32] =   { 0x60, 0xD5, 0x5B, 0x03, 0x58, 0x6C, 0xF0, 0x13, 
                               0x49, 0x06, 0x75, 0xA1, 0x74, 0x0E, 0x81, 0xD9, 
                               0xB0, 0x51, 0xBE, 0x05, 0xB0, 0x62, 0x3F, 0xA2, 
                               0x0E, 0x8D, 0x5B, 0x13, 0xB2, 0xD3, 0x88, 0xA7 };
    CK_BYTE derive_key_etalon[32] = { 0x2B, 0x1A, 0x84, 0xD4, 0xB5, 0xEE, 0x0F, 0x99, 
                                      0xBC, 0x2A, 0xE8, 0x7D, 0xAA, 0x5E, 0x23, 0x36, 
                                      0xC3, 0xC9, 0xAA, 0xC7, 0x3C, 0xF1, 0x1B, 0x4B, 
                                      0x4A, 0x3B, 0x19, 0x85, 0x68, 0xF8, 0x29, 0x63 };
    CK_BYTE derive_key[32] = {0};

    CK_BYTE kqpk[32] = {0};
    CK_BYTE kqpk_etalon[32] = { 0x72, 0x6F, 0xEF, 0x08, 0x0B, 0xDD, 0x66, 0x9F, 
                                0x2A, 0xE4, 0xE8, 0xA7, 0xE4, 0xD1, 0x6F, 0x02, 
                                0xF8, 0x4B, 0x74, 0x37, 0x9F, 0xC4, 0x15, 0xFA, 
                                0x73, 0xD5, 0x2C, 0x7A, 0x2E, 0xE6, 0x92, 0xD8 };

    kdf1(handle.session(), funcs, base_key, key_ctr, derive_key, kqpk);
    EXPECT_EQ(memcmp(derive_key, derive_key_etalon, 32), 0);
    EXPECT_EQ(memcmp(kqpk, kqpk_etalon, 32), 0);
}

TEST(CryptoTest, kdf1_invalid_cases)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    CK_BYTE key_ctr[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    CK_BYTE base_key[32] =   { 0x60, 0xD5, 0x5B, 0x03, 0x58, 0x6C, 0xF0, 0x13, 
                               0x49, 0x06, 0x75, 0xA1, 0x74, 0x0E, 0x81, 0xD9, 
                               0xB0, 0x51, 0xBE, 0x05, 0xB0, 0x62, 0x3F, 0xA2, 
                               0x0E, 0x8D, 0x5B, 0x13, 0xB2, 0xD3, 0x88, 0xA7 };
    CK_BYTE derive_key[32] = {0};

    CK_BYTE kqpk[32] = {0};
 
    EXPECT_EQ(kdf1(handle.session(), funcs, nullptr, key_ctr, derive_key, kqpk), -1);
    EXPECT_EQ(kdf1(handle.session(), funcs, base_key, nullptr, derive_key, kqpk), -1);
    EXPECT_EQ(kdf1(handle.session(), funcs, base_key, key_ctr, nullptr, kqpk), -1);
    EXPECT_EQ(kdf1(handle.session(), funcs, base_key, key_ctr, derive_key, nullptr), -1);
}

TEST(CryptoTest, kdfg)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();   

    // Компонента Rand и ее длина
    CK_BYTE rand_comp[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 
                            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    // Компонента QRand и ее длина
    CK_BYTE qrand_comp[] = { 0x13, 0x20, 0x27, 0xA3, 0x4B, 0x15, 0x6C, 0xF7, 
                             0x83, 0x19, 0x43, 0xFB, 0xCF, 0xBD, 0x1E, 0x2F, 
                             0x1A, 0x46, 0x42, 0xBB, 0x4C, 0xF5, 0x67, 0x37, 
                             0x83, 0xF9, 0xBA, 0xBC, 0x1C, 0x3D, 0x6E, 0x7F };
    // Компонента QRand и ее длина
    CK_BYTE id_dpu_pair[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
                            
    CK_BYTE qpk_1_etalon[32] = {0xB4, 0x13, 0x69, 0xF7, 0x7D, 0xA9, 0x30, 0xC7, 
                                0x33, 0x9C, 0xCE, 0xC7, 0xDE, 0x28, 0x6F, 0x1F, 
                                0x48, 0x65, 0x9B, 0x36, 0x9D, 0xD4, 0x69, 0x5A, 
                                0xC2, 0x80, 0xC4, 0x19, 0xE0, 0xB8, 0xCE, 0xFA};

    CK_BYTE qpk_2_etalon[32] = {0x6C, 0xC2, 0x47, 0x01, 0x28, 0x1A, 0x76, 0x4A, 
                                0xE1, 0xC8, 0x88, 0x52, 0x24, 0x39, 0xB2, 0x05, 
                                0x7B, 0xEC, 0x78, 0x38, 0xF2, 0x63, 0xF2, 0x89, 
                                0xCB, 0x76, 0x87, 0x8B, 0x3E, 0xC3, 0x52, 0x7F};

    CK_ULONG id_dpu_pair_size = sizeof(id_dpu_pair) / sizeof(CK_BYTE);
    // ID набора целевых ключей
    const CK_ULONG m_size = 6;
    CK_BYTE m[m_size] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};
    // 30 целевых ключей по 256 байт
    const CK_ULONG key_len = 32;
    const CK_ULONG qpk_kit_count = 2;
    CK_BYTE qpk[qpk_kit_count][key_len] = {0};
    
    kdfg(handle.session(), funcs, rand_comp, qrand_comp, id_dpu_pair, id_dpu_pair_size, m, m_size, qpk, qpk_kit_count);
    EXPECT_EQ(memcmp(qpk[0], qpk_1_etalon, 32), 0);
    EXPECT_EQ(memcmp(qpk[1], qpk_2_etalon, 32), 0);
}

TEST(CryptoTest, kdfg_invalid_cases)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();   

    // Компонента Rand и ее длина
    CK_BYTE rand_comp[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 
                            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    // Компонента QRand и ее длина
    CK_BYTE qrand_comp[] = { 0x13, 0x20, 0x27, 0xA3, 0x4B, 0x15, 0x6C, 0xF7, 
                             0x83, 0x19, 0x43, 0xFB, 0xCF, 0xBD, 0x1E, 0x2F, 
                             0x1A, 0x46, 0x42, 0xBB, 0x4C, 0xF5, 0x67, 0x37, 
                             0x83, 0xF9, 0xBA, 0xBC, 0x1C, 0x3D, 0x6E, 0x7F };
    // Компонента QRand и ее длина
    CK_BYTE id_dpu_pair[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
  
    CK_ULONG id_dpu_pair_size = sizeof(id_dpu_pair) / sizeof(CK_BYTE);
    // ID набора целевых ключей
    const CK_ULONG m_size = 6;
    CK_BYTE m[m_size] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};
    // 30 целевых ключей по 256 байт
    const CK_ULONG key_len = 32;
    const CK_ULONG qpk_kit_count = 2;
    CK_BYTE qpk[qpk_kit_count][key_len] = {0};
    
    EXPECT_EQ(kdfg(handle.session(), funcs, nullptr, qrand_comp, id_dpu_pair, id_dpu_pair_size, m, m_size, qpk, qpk_kit_count), -1);
    EXPECT_EQ(kdfg(handle.session(), funcs, rand_comp, nullptr, id_dpu_pair, id_dpu_pair_size, m, m_size, qpk, qpk_kit_count), -1);
    EXPECT_EQ(kdfg(handle.session(), funcs, rand_comp, qrand_comp, nullptr, id_dpu_pair_size, m, m_size, qpk, qpk_kit_count), -1); 
}

TEST(CryptoTest, key_gen_256)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    CK_BYTE key[31] = {0};
    EXPECT_EQ(key_gen_256(handle.session(), nullptr, key), -1);  
    EXPECT_EQ(key_gen_256(handle.session(), funcs, nullptr), -1);  
}

TEST(CryptoTest, key_gen_256_invalid_cases)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    CK_BYTE key[32] = {0};
    CK_BYTE key_etalon[32] = {0};
    key_gen_256(handle.session(), funcs, key);  
    EXPECT_NE(memcmp(key, key_etalon, 32), 0);
}

TEST(CryptoTest, container_form)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
   
    CK_BYTE label[8] = {0x00, 0x00, 0x00, 0x00, 0x4B, 0x51, 0x50, 0x4B};
    CK_BYTE m[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0a};
    CK_BYTE cs_kw[1] = {0x00}; // Кузнечик
    CK_BYTE key_id[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    CK_BYTE key_ctr[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}; 
    CK_BYTE dpu_id_initiator[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    CK_BYTE dpu_id_initiator_pair[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    CK_BYTE dpu_id_sender[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};
    CK_BYTE dpu_id_receiver[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    CK_BYTE kexp[48] = {0xF9, 0x4E, 0xFE, 0x30, 0xF9, 0x41, 0x89, 0xB1,
                        0x25, 0x48, 0x20, 0xEB, 0x23, 0x59, 0x41, 0x0B,
                        0x5D, 0x47, 0x9D, 0x04, 0xE2, 0x4F, 0x45, 0xD4,
                        0xE3, 0x7F, 0x81, 0x06, 0xBE, 0xE6, 0x8A, 0x83,
                        0x13, 0x2E, 0xF8, 0xD0, 0xED, 0xEB, 0x8B, 0x11,
                        0x52, 0x20, 0xAF, 0x88, 0xF5, 0x0B, 0xA3, 0x39};

    Container container;
    container_form(&container, label, 8, m, 6, cs_kw, 1, key_id, 16, key_ctr, 8, 
                    dpu_id_initiator, 16, dpu_id_initiator_pair, 16, dpu_id_sender, 16, 
                    dpu_id_receiver, 16, kexp, 48);

    Container etalon_container;
    memcpy(etalon_container.label, label, 8);
    memcpy(etalon_container.m, m, 6);
    memcpy(etalon_container.cs_kw, cs_kw, 1);
    memcpy(etalon_container.id_base_key, key_id, 16);
    memcpy(etalon_container.use_key_ctr, key_ctr, 8);
    memcpy(etalon_container.dpu_id_initiator, dpu_id_initiator, 16);
    memcpy(etalon_container.dpu_id_initiator_pair, dpu_id_initiator_pair, 16);
    memcpy(etalon_container.dpu_id_sender, dpu_id_sender, 16);
    memcpy(etalon_container.dpu_id_receiver, dpu_id_receiver, 16);
    memcpy(etalon_container.kexp, kexp, 48);

    EXPECT_EQ(memcmp(&container, &etalon_container, 151), 0);
}

TEST(CryptoTest, component_extraction)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    Container container;   
    memset(&container, 0, 151);
    
    CK_BYTE rand_comp[32] = {0};
    key_gen_256(handle.session(), funcs, rand_comp);
    CK_BYTE rand_etalon[32] = {0};

    CK_BYTE kqpk[32] = {0};
    key_gen_256(handle.session(), funcs, kqpk);

    CK_BYTE rand_kexp[48] = {0};
    CK_ULONG kexp_size = 48;

    CK_BYTE label[32] = {0};
    CK_BYTE id_qpk[6] = {0};
    CK_BYTE cs_kw[1] = {0};
    CK_BYTE id_base_key[16] = {0};
    CK_BYTE key_ctr[8] = {0};
    CK_BYTE dpu_id_initiator[16] = {0};
    CK_BYTE dpu_id_initiator_pair[16] = {0};
    CK_BYTE dpu_id_sender[16] = {0};
    CK_BYTE dpu_id_reciever[16] =  {0}; 

    kexp15_kuzn(
        handle.session(), 
        funcs, 
        kqpk, 
        32, 
        rand_comp,
        32, 
        key_ctr, 
        8, 
        rand_kexp,
        &kexp_size
    );

    // Заполнение информации контейнера компоненты Rand
    memcpy(container.label, label, 8);
    memcpy(container.m, id_qpk, 6);
    memcpy(container.cs_kw, cs_kw, 1);
    memcpy(container.id_base_key, id_base_key, 16);
    memcpy(container.use_key_ctr, key_ctr, 8);
    memcpy(container.dpu_id_initiator,dpu_id_initiator, 16);
    memcpy(container.dpu_id_initiator_pair, dpu_id_initiator_pair, 16);
    memcpy(container.dpu_id_sender, dpu_id_sender, 16);
    memcpy(container.dpu_id_receiver, dpu_id_reciever, 16);
    memcpy(container.kexp, rand_kexp, 48);

    // Контейнер зашифровывался на счетчике 0 и расшифровываться долже также
    CK_BYTE key_ctr2[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
    component_extraction(handle.session(), funcs, &container, kqpk, 32, key_ctr2, 8, rand_etalon);

    EXPECT_EQ(memcmp(rand_comp, rand_etalon, 32), 0);
}

TEST(CryptoTest, component_extraction_invalid_cases)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    Container container;   
    memset(&container, 0, 151);
    
    CK_BYTE rand_comp[32] = {0};
    key_gen_256(handle.session(), funcs, rand_comp);
    CK_BYTE rand_etalon[32] = {0};

    CK_BYTE kqpk[32] = {0};
    key_gen_256(handle.session(), funcs, kqpk);

    CK_BYTE rand_kexp[48] = {0};
    CK_ULONG kexp_size = 48;

    CK_BYTE label[32] = {0};
    CK_BYTE id_qpk[6] = {0};
    CK_BYTE cs_kw[1] = {0};
    CK_BYTE id_base_key[16] = {0};
    CK_BYTE key_ctr[8] = {0};
    CK_BYTE dpu_id_initiator[16] = {0};
    CK_BYTE dpu_id_initiator_pair[16] = {0};
    CK_BYTE dpu_id_sender[16] = {0};
    CK_BYTE dpu_id_reciever[16] =  {0}; 

    kexp15_kuzn(
        handle.session(), 
        funcs, 
        kqpk, 
        32, 
        rand_comp,
        32, 
        key_ctr, 
        8, 
        rand_kexp,
        &kexp_size
    );

    // Заполнение информации контейнера компоненты Rand
    memcpy(container.label, label, 8);
    memcpy(container.m, id_qpk, 6);
    memcpy(container.cs_kw, cs_kw, 1);
    memcpy(container.id_base_key, id_base_key, 16);
    memcpy(container.use_key_ctr, key_ctr, 8);
    memcpy(container.dpu_id_initiator,dpu_id_initiator, 16);
    memcpy(container.dpu_id_initiator_pair, dpu_id_initiator_pair, 16);
    memcpy(container.dpu_id_sender, dpu_id_sender, 16);
    memcpy(container.dpu_id_receiver, dpu_id_reciever, 16);
    memcpy(container.kexp, rand_kexp, 48);

    // Не возвращаем значение счетчика 
    component_extraction(handle.session(), funcs, &container, kqpk, 32, key_ctr, 8, rand_etalon);
    EXPECT_NE(memcmp(rand_comp, rand_etalon, 32), 0);

    // Контейнер зашифровывался на счетчике 0 и расшифровываться долже также
    CK_BYTE key_ctr2[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 

    // Изменяем компоненту rand
    increment_ctr(rand_comp, 32);
    component_extraction(handle.session(), funcs, &container, kqpk, 32, key_ctr2, 8, rand_etalon);
    EXPECT_NE(memcmp(rand_comp, rand_etalon, 32), 0);
}

// ГОСТ P 1323565.1.017-2018 Приложение Б алгоритмы экспорта KExp15 и импорта KImp15 ключа для шифра «Кузнечик»
TEST(GostTest, kexp_kuzn_test)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    
    CK_RV rv = CKR_OK;
    
    CK_OBJECT_HANDLE extraction_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE extracted_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrapped_key_handle = CK_INVALID_HANDLE;
    
    // Вектор инициализации из ГОСТ P 1323565.1.017-2018
    CK_BYTE iv[] = {
        0x09, 0x09, 0x47, 0x2D, 0xD9, 0xF2, 0x6B, 0xE8,
    };
    
    CK_MECHANISM kexp_mech = { CKM_KUZNECHIK_KEXP_15_WRAP, iv, sizeof(iv) };
    
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;
    
    CK_KEY_TYPE key_type = CKK_KUZNECHIK;
    CK_KEY_TYPE twin_key_type = CKK_KUZNECHIK_TWIN_KEY;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    

    CK_BYTE extraction_key_value[] = {
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    };
    
    CK_ATTRIBUTE extraction_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_ENCRYPT, &b_true, sizeof(b_true)},
        {CKA_DECRYPT, &b_true, sizeof(b_true)},
        {CKA_VALUE, extraction_key_value, sizeof(extraction_key_value)},
    };
    
    CK_BYTE extracted_key_value[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    };
    
    CK_ATTRIBUTE extracted_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &twin_key_type, sizeof(twin_key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_WRAP, &b_true, sizeof(b_true)},
        {CKA_UNWRAP, &b_true, sizeof(b_true)},
        {CKA_VALUE, extracted_key_value, sizeof(extracted_key_value)},
    };
    
    CK_ATTRIBUTE unwrapped_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_EXTRACTABLE, &b_true, sizeof(b_true)},
        {CKA_SENSITIVE, &b_false, sizeof(b_false)},
    };
    
    // KEXP из ГОСТ P 1323565.1.017-2018 (Эталонное значение)
    CK_BYTE ETALON[] = {
        0xE3, 0x61, 0x84, 0xE8, 0x4E, 0x8D, 0x73, 0x6F,
        0xF3, 0x6C, 0xC2, 0xE5, 0xAE, 0x06, 0x5D, 0xC6,
        0x56, 0xB2, 0x3C, 0x20, 0xF5, 0x49, 0xB0, 0x2F,
        0xDF, 0xF8, 0x8E, 0x1F, 0x3F, 0x30, 0xD8, 0xC2,
        0x9A, 0x53, 0xF3, 0xCA, 0x55, 0x4D, 0xBA, 0xD8,
        0x0D, 0xE1, 0x52, 0xB9, 0xA4, 0x62, 0x5B, 0x32,
    };
    
    rv = funcs->C_CreateObject(handle.session(), extraction_key_template,
    sizeof(extraction_key_template) / sizeof(CK_ATTRIBUTE), &extraction_key_handle);

    rv = funcs->C_CreateObject(handle.session(), extracted_key_template,
    sizeof(extracted_key_template) / sizeof(CK_ATTRIBUTE), &extracted_key_handle);
    
    CK_BYTE value[sizeof(ETALON)];
    CK_ULONG valueLength = sizeof(value);

    rv = funcs->C_WrapKey(handle.session(), &kexp_mech, extracted_key_handle,
    extraction_key_handle, value, &valueLength);

    rv = funcs->C_UnwrapKey(handle.session(), &kexp_mech, extracted_key_handle, ETALON, sizeof(ETALON),
    unwrapped_key_template, sizeof(unwrapped_key_template) / sizeof(CK_ATTRIBUTE), &unwrapped_key_handle);
    EXPECT_EQ(rv, 0);
}

// ГОСТ Р 50.1.113 - 2016 Приложение A. Алгоритм диверсификации KDF_GOSTR3411_2012_256 пункт 11
// ГОСТ Р 50.1.113 - 2016 Приложение A. Алгоритм диверсификации KDF_GOSTR3411_2012_256 пункт 11
TEST(GostTest, kdf_three_test)
{
    PKCS11Handle handle("../build/subprojects/spbpkcs11/libspbpkcs11.so");
    handle.login("11111111", "useruser");
    CK_FUNCTION_LIST_PTR funcs = handle.functionList();
    
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE base_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE derived_key_handle = CK_INVALID_HANDLE;
    
    CK_BYTE label[] = { 0x26, 0xbd, 0xb8, 0x78 };
    CK_BYTE seed[] = { 
        0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78 
    };
    
    CK_KDF_TREE_GOST_PARAMS deriveParams = {
        sizeof(label), label,
        sizeof(seed), seed,
        1,   // ulR
        64,  // ulL
        32   // ulOffset
    };
    
    CK_MECHANISM deriveMechanism = { 
        CKM_KDF_TREE_GOSTR3411_2012_256, 
        &deriveParams, 
        sizeof(deriveParams) 
    };
    
    CK_BBOOL b_true = CK_TRUE;
    CK_BBOOL b_false = CK_FALSE;
    CK_KEY_TYPE key_type = CKK_KUZNECHIK;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    
    CK_BYTE base_key_value[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    
    CK_ATTRIBUTE base_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_DERIVE, &b_true, sizeof(b_true)},
        {CKA_VALUE, base_key_value, sizeof(base_key_value)},
    };
    
    CK_BYTE ETALON[] = {
        0x07, 0x4c, 0x93, 0x30, 0x59, 0x9d, 0x7f, 0x8d,
        0x71, 0x2f, 0xca, 0x54, 0x39, 0x2f, 0x4d, 0xdd,
        0xe9, 0x37, 0x51, 0x20, 0x6b, 0x35, 0x84, 0xc8,
        0xf4, 0x3f, 0x9e, 0x6d, 0xc5, 0x15, 0x31, 0xf9,
    };
    
    CK_ATTRIBUTE derived_key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &b_false, sizeof(b_false)},
        {CKA_PRIVATE, &b_true, sizeof(b_true)},
        {CKA_EXTRACTABLE, &b_true, sizeof(b_true)},
        {CKA_SENSITIVE, &b_false, sizeof(b_false)},
    };

    rv = funcs->C_CreateObject(
        handle.session(), 
        base_key_template, 
        sizeof(base_key_template) / sizeof(CK_ATTRIBUTE), 
        &base_key_handle
    );
    
    rv = funcs->C_DeriveKey(
        handle.session(), 
        &deriveMechanism, 
        base_key_handle,
        derived_key_template, 
        sizeof(derived_key_template) / sizeof(CK_ATTRIBUTE), 
        &derived_key_handle
    );
    
    CK_BYTE value[sizeof(ETALON)];
    CK_ATTRIBUTE key_attribute = { 
        CKA_VALUE, 
        value, 
        sizeof(value) 
    };
    
    rv = funcs->C_GetAttributeValue(
        handle.session(), 
        derived_key_handle, 
        &key_attribute, 
        1
    );
    
    EXPECT_EQ(rv, CKR_OK);
}
int main(int argc, char* argv[])
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
