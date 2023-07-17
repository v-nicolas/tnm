#!/bin/bash

nc -l 1234 &
NC_PID=$!

#for I in {1..1}; do
#    echo i = $I
#./tnmctl --add \
#         --hostname localhost --port 80 \
#         --monit http --http-method GET --http-path "/" \
#         --timeout 5 --frequency 15
#done

sleep 2


#enable api stats
curl -X POST 127.0.0.1:8000/ \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 1,"monitoring_type": 2,"timeout": 5,"frequency": 15,"port": 1234,"hostname": "localhost","uuid": "a185c2c0-3333-3333-3333-9c3494211111","http_method": "GET","http_path": "/"}' | jq

# error
curl -X POST 127.0.0.1:8000/toto \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 1,"monitoring_type": 2,"timeout": 5,"frequency": 15,"port": 1234,"hostname": "localhost","uuid": "a185c2c0-3333-3333-3333-9c3494211111","http_method": "GET","http_path": "/"}' | jq

# get stats
# disable
# get stats
# enable
# error
# get stats
# disable
# get stats


curl -X POST 127.0.0.1:8000/ \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 1,"monitoring_type": 2,"timeout": 5,"frequency": 15,"port": 1234,"hostname": "localhost","uuid": "a185c2c0-3333-3333-3333-9c3494211111","http_method": "GET","http_path": "/"}' | jq

sleep 1



curl -X GET 127.0.0.1:8000/ \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 4}' | jq

echo "Kill nc and delete uuid ..."
kill -9 $NC_PID

curl -X DELETE 127.0.0.1:8000/ \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 2,"uuid": "a185c2c0-3333-3333-3333-9c3494211111"}' | jq


curl -X GET 127.0.0.1:8000/ \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 4}' | jq
