crypto-proxy is designed as a module for Apache httpd, and is configured with Apache httpd config files.



In the following example,

we have a GnuPG key pair with the ID `8D9606B41E45B90757703717A3B1A1BA2A8036AC`,

and a passphrase `12342234`,

and the GnuPG keyring is placed at `/var/www/.gnupg/`.

We place the scripts in loader.js directory under `/js/`, 

and the website's domain is `jinzihao.me`,

and we serve static content of the website on `http.jinzihao.me`.



Example config for http domain:

(Using mod_cache and mod_cache_disk to cache the signed version of static content)

```
SetOutputFilter INFLATE;CRYPTO-PROXY-REWRITE;CRYPTO-PROXY-SIGN;DEFLATE
CryptoProxyEnable On
CryptoProxyInherit On
CryptoProxyJavaScriptPath "/js/"
CryptoProxyPrivateKey "8D9606B41E45B90757703717A3B1A1BA2A8036AC"
CryptoProxyPassphrase "12342234"
CryptoProxyGnuPGRootDir "/var/www/.gnupg/"
CryptoProxyHttpDomain "http.jinzihao.me"
CryptoProxyHttpsDomain "jinzihao.me"

CacheLock on
CacheLockPath /tmp/mod_cache-lock
CacheLockMaxAge 5

CacheEnable disk /
CacheRoot "/var/cache/apache2/mod_cache_disk"
CacheDirLevels 3
CacheDirLength 5
CacheIgnoreCacheControl On
CacheMaxFileSize 67108864
CacheIgnoreNoLastMod On
CacheDefaultExpire 86400

<IfModule mod_expires.c>
    ExpiresActive on
    ExpiresDefault "access plus 1 months"
    ExpiresByType text/html "access plus 1 months"
    ExpiresByType image/gif "access plus 1 months"
    ExpiresByType image/jpg "access plus 1 months"
    ExpiresByType image/jpeg "access plus 1 months"
    ExpiresByType image/png "access plus 1 months"
    ExpiresByType text/js "access plus 1 months"
    ExpiresByType text/javascript "access plus 1 months"
</IfModule>
```

Example config for https domain:
```
SetOutputFilter INFLATE;CRYPTO-PROXY-REWRITE;DEFLATE
CryptoProxyEnable On
CryptoProxyInherit On
CryptoProxyJavaScriptPath "/js/"
CryptoProxyPrivateKey "8D9606B41E45B90757703717A3B1A1BA2A8036AC"
CryptoProxyPassphrase "12342234"
CryptoProxyGnuPGRootDir "/var/www/.gnupg/"
CryptoProxyHttpDomain "http.jinzihao.me"
CryptoProxyHttpsDomain "jinzihao.me"
```
