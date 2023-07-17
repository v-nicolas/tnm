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
