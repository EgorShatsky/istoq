#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <unistd.h>
#include <sys/time.h>

enum LOG_MSG { 
    INFO  = 0, 
    ERROR = 1, 
    DEBUG = 2 
};

class Logger 
{
public:
    Logger(std::string base_path);
    ~Logger() 
    {
        if (logfile.is_open()) 
        {
            logfile.close();
        }
    }

    void log(std::string msg, LOG_MSG level);

private:
    std::ofstream logfile;
    std::string m_base_path;
    std::string filename;
    std::mutex mtx;
    static constexpr const char* msg_types[3] = {"INFO", "ERROR", "DEBUG"};
};

#endif // LOGGER_H