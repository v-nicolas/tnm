#!/bin/bash

nc -l 1234 &
NC_PID=$!

./tnmctl --add \
         --hostname localhost --port 1234 \
         --monit http --http-method GET --http-path "/" \
         --timeout 5 --frequency 15 \
         --uuid a185c2c0-3333-3333-3333-9c3494211111

sleep 3

./tnmctl -l | jq

echo "Kill nc and delete uuid ..."
kill -9 $NC_PID
./tnmctl -r --uuid a185c2c0-3333-3333-3333-9c3494211111

sleep 1

./tnmctl -l | jq


curl -X POST 127.0.0.1:8000/host \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 1,"monitoring_type": 2,"timeout": 5,"frequency": 15,"port": 1234,"hostname": "localhost","uuid": "a185c2c0-3333-3333-3333-9c3494211111","http_method": "GET","http_path": "/"}' | jq


curl -X DELETE 127.0.0.1:8000/host \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 2,"uuid": "a185c2c0-3333-3333-3333-9c3494211111"}' | jq


curl -X GET 127.0.0.1:8000/host \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer toto" \
     -d '{"command": 4}' | jq
