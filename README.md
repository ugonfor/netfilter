# netfilter

## How to use
### requirement
```
sudo apt install libnetfilter-queue-dev
sudo apt install g++
```

### Use
```shell
syntax : ./netfilter <host>
for debug mode, add -d option
sample : ./netfilter test.gilgil.net [-d]
```

## Description
* `host` is host name which we target to ban
* Should run this as root user
* execute `./start.sh` before run this
* execute `./stop.sh` after run this

## code
*  This is checklist
    * is tcp?
    * is Port 80?
    * is tcp data exist?
    * is tcp data start with http method?
    * is http header have 'host'?
    * is host equal to argv[1]?
    * than return NF_DROP!
