# tnm

Description:
```
Tiny network monitoring - Check that your server is online.
```

### COMPILATION
```
    make release
    sudo make install
```

### DEPENDENCIES

    1. libmongoc (with APT system: apt install libmongoc-dev)
    2. libssl (with APT system: apt install libssl-dev)

    Possibility to disable thios option.
    For this delete in Makefile this line:
```
                            -DHAVE_SSL -DHAVE_MONGOC \
```

### ADD NEW HOST
```
    Ping IP version 6
    tnmctl --add \
        --hostname localhost --ip-version 6 \
        --monit ping \
        --timeout 5 --frequency 15 \
        [--uuid UUID [optional field]]


    HTTPS (application choose ipv6 or ipv4)
    ./tnmctl --add \
         --hostname "www.site.com" --ssl --port 443 \
         --monit http --http-method GET --http-path "/" \
         --timeout 5 --frequency 15 \
         --uuid a185c2c0-3333-3333-3333-9c3494211111
```

### LIST HOSTS
```
tnmctl -l

Possiblity to clean output with jq: tnmctl -l | jq
```

### DELETE HOST
```
tnmctl -r --uuid UUID
```

### UPDATE HOST
    Not yen possible, just delete and add new host with the modification.
