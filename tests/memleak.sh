#!/bin/zsh

if [ $# != 1 ]; then
    echo "Missing binary name: ./memleak.sh binary_name"
    exit 1
fi

BNAME=$1

RES=$(valgrind ${BNAME} 2>&1)
if [ $? != 0 ]; then
    echo ${RES}
    exit 1
fi

LINE="${RES#*"heap usage: "}"
ARR=(${(@s: :)$(echo $LINE | cut -d " "  -f 1,3)})

if [ ${ARR[1]} != ${ARR[2]} ]; then
    echo "Memory leak (alloc:${ARR[1]}, free: ${ARR[2]})"
    exit 2
fi

exit 0
