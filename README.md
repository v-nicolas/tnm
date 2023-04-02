# tnm

TNM is short for **Tiny Network Monitoring**, it is a system that enables you to check that your servers are online.

## Table of Contents
1. [Compilation](#compilation)
2. [Dependencies](#dependencies)
   1. [APIRest](#apirest)
   2. [Socket unix](#socket-unix)
3. [Dial with tnm](#dial-with-tnm)
4. [Database](#database)
   1. [File](#file)
   2. [MongoDB](#mongodb)
5. [Add new host](#Add-new-host)
6. [Suspend and resume the monitoring](#suspend-and-resume-the-monitoring)
   1. [Suspend](#suspend)
   2. [Resume](#resume)
7. [Host state](#host-state)
8. [List hosts](#list-hosts)
9. [Delete host](#delete-host)
10. [Update host](#update-host)
11. [Help](#help)

### Compilation

```
    make release
    sudo make install
```

### Dependencies

TNM currently has the following dependencies:

1. `libmongoc`, which can be installed on machines with the apt package manager (like Debian) 
using the command `apt install libmongoc-dev`
2. `libssl` which can be installed on machines with the apt package manager 
using `apt install libssl-dev`

It is possible to disable the this option by removing the following line from the Makefile:

```
-DHAVE_SSL -DHAVE_MONGOC \
```

### Dial with tnm
##### APIRest
API Rest is enable by default, to disable it set argument
```
tnm --disable-api-rest
```
The default port is `8000`
To use another port, use argument
```
tnm --http-port PORT
```
By default the api rest server accept IPv4 and IPv6 connection.
For accept only IPv4 or IPv6 connection use argument
```
tnm --http-ipv4-only
tnm --http-ipv6-only
```

To define a specific bind address (example localhost)
```
tnm --http-bind-addr 127.0.0.1
```

##### Socket unix
It is not possible to disable it (for moment).
By default the socket path is `/tmp/nm_ctl.sock`
To change it for tnm and tnmctl, use argument
```
--ctl-sock-path PATH
```

### Database
By default database is mandatory, but if you don't want use a database set argument
```
tnm --no-db
```

##### File
For use a classic file like a database (JSON format)
```
tnm --db-file PATH
```

##### MongoDB
For use MongoDB, you need to compil with flag HAVE_MONGOC (the flag is set by default)
and set argument
```
tnm --db-uri [username:password@]host[:port]
```
For more detail see documentation [MongoDB URI](https://www.mongodb.com/docs/manual/reference/connection-string/)

### Add new host
If host UUID not defined, is set when tnm add host. Is returned in response.
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

### Suspend and resume the monitoring
##### SUSPEND
If timeout is not defined, the monitoring will be suspended until the resume command 
For all hosts
```
tnmctl --suspend [--timeout VALUE]
```

For one host
```
tnmctl --suspend --uuid UUID [--timeout VALUE] 
```

##### RESUME
For all hosts
```
tnmctl --resume
```

For one host
```
tnmctl --resume --uuid [UUID]
```

### Host state
When the host state changed, the database is upated and optional shell script is executed
Execute a shell script
```
tnm --script PATH
```

### List hosts

To list hosts, use the `-l` flag:
```
tnmctl -l

```

It is possible to use [jq](https://stedolan.github.io/jq/) to format the output data for easier reading.
```
tnmctl -l | jq
```

### Delete host

To delete a host, use the `-r` flag to specify deletion, and the `--uuid` flag to specify the UUID of the host to delete.
```
tnmctl -r --uuid UUID
```

### Update host
It is not yet possible to update a host, but deleting the host and adding the new version has the same effect.

### Help
To get helper for tnm and tnmctl, use the -h or --help argument
