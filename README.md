# istoq
Ключевая система сети шифрованной связи с использованием квантовой криптографической системы выработки и распределения ключей

### Получение списка подключенных клиентов
#### Клиент вводит команду "LIST"
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/list.jpeg) 

#### Логи выполнения команды
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/client_clog.jpeg)

### Получение набора целевых ключей
#### Клиент вводит команду "GET KEY <ID клиента из списка подключенных клиентов>"
![App Screenshot]((https://github.com/EgorShatsky/istoq/blob/main/pic/get_key.jpeg)) 

#### Результатом является получение идентичного набора криптографических ключей
#### Целевой ДПУ клиент №1
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/client_log_key_1.jpeg)

#### Целевой ДПУ клиент №2
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/client_log_key_2.jpeg)

### Отключение от сервера
#### Клиент вводит команду "STOP"
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/stop.jpeg)

#### Логи
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/stop_log.jpeg)

### Остановка работы сервера
#### Команда сервера "EXIT"
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/exit_server.jpeg)

#### Логи
![App Screenshot](https://github.com/EgorShatsky/istoq/blob/main/pic/exit_server_log.jpeg)
