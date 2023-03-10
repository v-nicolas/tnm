#!/bin/zsh

COMPIL=1
TEST=1

if [ $# -gt 0 ]; then
    if [ "$1" = "-x" ]; then
	COMPIL=0
    elif [ "$1" = "-c" ]; then
	TEST=0
    fi
fi

compil_res() {
    if [ $? != 0 ]; then
	echo "Fail"
	exit 1
    else
	echo "Ok"
    fi
}

# arg 1: test name, example mongo, command
# arg 2: binary path 
test_bin() {
    if [ ${TEST} -eq 0 ]; then
	return
    fi
    
    echo -n "Test ${1} ... "
    TEST_RES=$(./memleak.sh "$2")
    RET=$?
    
    if [ "${RET}" -eq 0 ]; then
	echo "Ok"
    elif [ "${RET}" -eq 2 ]; then
	echo ${TEST_RES}
    else
	echo "Fail"
    fi
}

### Mongo
#########
if [ ${COMPIL} -eq 1 ]; then
    echo -n "Compil mongo test ... "
    gcc -o mongo_test test_mongo.c ../src/nm.c ../src/command.c ../src/icmp.c ../src/db.c ../src/db_file.c ../src/host.c ../src/misc.c ../lib/*.c -I../lib/ -I../src/ -I/usr/include/libmongoc-1.0 -lmongoc-1.0 -lbson-1.0 -I/usr/include/libbson-1.0 -lpthread -lssl -lcrypto -DHAVE_SSL -DHAVE_MONGOC -g2 -O0 1>/dev/null
    compil_res
fi
test_bin "mongo" ./mongo_test


## Command
##########
if [ ${COMPIL} -eq 1 ]; then
    echo -n "Compil command test ... "
    gcc -o cmd_test test_command.c ../src/nm.c ../src/icmp.c ../src/db.c ../src/db_file.c ../src/mongo.c ../src/host.c ../src/misc.c ../lib/*.c -I../lib/ -I../src/ -I/usr/include/libmongoc-1.0 -lmongoc-1.0 -lbson-1.0 -I/usr/include/libbson-1.0 -lpthread -lssl -lcrypto -DUSE_SSL -g2 -O0 1>/dev/null
    compil_res
fi
test_bin "command" ./cmd_test

### lib HTTP
############
if [ ${COMPIL} -eq 1 ]; then
    echo -n "Compil lib/http test ..."
    gcc -g2 -o lib_http_test test_lib_http.c ../lib/mem.c ../lib/sbuf.c ../lib/str.c ../lib/log.c ../lib/file_utils.c  1>/dev/null
    compil_res
fi
test_bin "mongolib_http" ./lib_http_test
