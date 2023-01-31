#!/bin/bash

echo "arg: ${1} ${2} $(date -d @${3}) ${4}" >> ./script/res_${1}
