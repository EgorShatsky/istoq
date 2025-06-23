#include <iostream>
#include <fstream>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "../include/logger.h"

Logger::Logger(std::string base_path) : m_base_path(base_path)
{
    filename = base_path + 
    "_" + std::to_string(getpid()) +
    ".txt";
    logfile.open(filename, std::ios::app);
    if (!logfile.is_open()) 
    {
        throw std::runtime_error("Невозможно открыть файл: " + filename);
    }
}

void Logger::log(std::string msg, LOG_MSG level)
{
    std::lock_guard<std::mutex> lock(mtx);
    struct timeval tv;
    struct tm t;
    char buf_t[64];
    
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &t);
    strftime(buf_t, sizeof(buf_t), "%T", &t);
    logfile << "[" << buf_t << "." 
            << tv.tv_usec / 1000 
            << "|" << msg_types[level] 
            << "|" << std::to_string(getpid()) << "] " 
            << msg << '\n' 
            << std::flush;
}