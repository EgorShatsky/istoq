# Конфигурирование проекта
project(
    'istoq',
    ['c', 'cpp'],
    version : '0.1',
    default_options : [
        'warning_level=3', 
        'c_compiler=gcc', 
        'cpp_compiler=g++', 
        'cpp_args=-Wall -Wextra -Werror',
    ]
)

# Зависимость для Google Test
gtest_dep = dependency('gtest', main: true, required: true)

# Подключение под проекта pkcs11
spbpkcs11_proj = subproject('spbpkcs11')

# Получение зависимостей из подпроекта
spbpkcs11_dep = spbpkcs11_proj.get_variable('spbpkcs11_dep')

# Инклюдники (файлы .h)
inc = include_directories('include')

# Исходники (файлы .cpp)
src = [
    'source/socket.cpp',
    'source/utils.cpp',
    'source/logger.cpp',
    'source/crypto.cpp'
]

# Исполняемый файл клиента
executable('client', 
    'source/client.cpp', 
    sources: src, 
    include_directories: inc,
    dependencies: [spbpkcs11_dep]
)

# Исполняемый файл сервера
executable('server', 
    'source/server.cpp', 
    sources: src, 
    include_directories: inc,
    dependencies: [spbpkcs11_dep]
)

# Юнит-тесты
test_exe = executable('tests',
    'unit_tests/test.cpp',
    sources: src,
    include_directories: inc,
    dependencies: [
        spbpkcs11_dep,
        gtest_dep
    ],
    cpp_args: [
        '-DUNIT_TESTING',
    ],
)

# Регистрация тестов для Meson test
test('Google Tests', test_exe)