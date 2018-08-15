all: lib_crypto_proxy_bucket.h lib_match.h mod_crypto_proxy.c uthash.h
	apxs -i -a -c -l gpgme mod_crypto_proxy.c

run:
	apachectl restart
