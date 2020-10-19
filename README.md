# Build
## Build binaries
```shell script
make build
```

## Build Deb Package
```shell script
apt install make devscripts debhelper build-essential dh-systemd
debuild -us -uc -b
```

# Usage
## Generate new CAPTHCAs database
```shell script
./nginx-captcha -generate=$AmountOfCAPTCHAs -db=$PathToDBFile
```
example:
```shell script
./nginx-captcha -generate=1000 -db=/var/cache/nginx-captcha/captcha.db
```
## Start nginx-captcha backend
```shell script
./nginx-captcha -db=/var/cache/nginx-captcha/captcha.db -address=unix:/run/nginx-captcha.sock
```
## Test nginx-captcha backend
```shell script
curl --unix-socket /run/nginx-captcha.sock http:/example.com
```

## Nginx configuration
The ./nginx dir contains the vhost configuration template.