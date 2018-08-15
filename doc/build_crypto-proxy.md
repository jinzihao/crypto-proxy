Install dependencies (on Ubuntu 16.04):
```
apt-get install apache2 apache2-dev libgpgme11-dev
```

Build:
```
make
```

Restart Apache httpd to enable crypto-proxy:

```
apachectl restart
```

