# tnm

TNM is short for **Tiny Network Monitoring**, it is a system that enables you to check that your servers are online.

### COMPILATION

```
    make release
    sudo make install
```

### DEPENDENCIES

TNM currently has the following dependencies:

1. `libmongoc`, which can be installed on machines with the apt package manager (like Debian) 
using the command `apt install libmongoc-dev`
2. `libssl` which can be installed on machines with the apt package manager 
using `apt install libssl-dev`

It is possible to disable the thios option by removing the following line from the Makefile:

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

To list hosts, use the `-l` flag:
```
tnmctl -l

```

It is possible to use [jq](https://stedolan.github.io/jq/) to format the output data for easier reading.
```
tnmctl -l | jq
```

### DELETE HOST

To delete a host, use the `-r` flag to specify deletion, and the `--uuid` flag to specify the UUID of the host to delete.
```
tnmctl -r --uuid UUID
```

### UPDATE HOST
It is not yet possible to update a host, but deleting the host and adding the new version has the same effect.
