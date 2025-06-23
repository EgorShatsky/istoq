#include <string>
#include <cstdint>
#include "../include/utils.h"

// Конвертация значения CK_ULONG в массив байт
void convert_ulong_to_bytes(CK_ULONG num, CK_ULONG num_size, CK_BYTE_PTR array) 
{
    CK_BYTE temp[4];
    temp[0] = (CK_BYTE)((num >> 24) & 0xFF); // Старший байт
    temp[1] = (CK_BYTE)((num >> 16) & 0xFF);
    temp[2] = (CK_BYTE)((num >> 8) & 0xFF);
    temp[3] = (CK_BYTE)(num & 0xFF);         // Младший байт

    CK_ULONG bytes_to_copy = (num_size < 4) ? num_size : 4;
    CK_ULONG start_index = 4 - bytes_to_copy;

    for (CK_ULONG i = 0; i < num_size; ++i) 
    {
        if (i < num_size - bytes_to_copy) 
        {
           array[i] = 0; // Заполняем нулями при num_size > 4
        } 
        else 
        {
           array[i] = temp[start_index + (i - (num_size - bytes_to_copy))];
        }
    }
}

// Конвертация значения CK_ULONG в массив байт
CK_ULONG convert_bytes_to_ulong(const CK_BYTE_PTR array, CK_ULONG num_size) 
{
    CK_ULONG result = 0;
    CK_ULONG bytes_to_process = (num_size > 4) ? 4 : num_size;
    CK_ULONG start_index = (num_size > 4) ? (num_size - 4) : 0;

    for (CK_ULONG i = 0; i < bytes_to_process; ++i) 
    {
        result = (result << 8) | array[start_index + i];
    }

    return result;
}

// Увеличение счетчика на +1
void increment_ctr(CK_BYTE_PTR ctr, CK_ULONG ctr_size) 
{
    for (int i = ctr_size - 1; i >= 0; --i) 
    {
        if (++ctr[i] != 0x00) 
        {
           return; // Нет переполнения
        }
    }
}

// Конвертация содержимого массива в строку (для красивой записи логов)
std::string bytes_to_hex_string(const CK_BYTE_PTR key, CK_ULONG key_size) 
{
    if (key_size == 0) 
    {
        return "";
    }

    const char hex_chars[] = "0123456789ABCDEF";
    std::string result;

    // Оптимизация: резервируем память заранее
    result.reserve(key_size * 3);

    for (CK_ULONG i = 0; i < key_size; ++i) 
    {
        CK_BYTE byte = key[i];
        result += hex_chars[(byte >> 4) & 0x0F]; // Старший полубайт
        result += hex_chars[byte & 0x0F];        // Младший полубайт
        
        // Добавляем пробел, если это не последний байт
        if (i != key_size - 1) 
        {
            result += ' ';
        }
    }

    return result;
}