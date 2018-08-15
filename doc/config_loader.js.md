Two variables in loader.js need to be configured:

- `HTTP_DOMAIN`: the domain used for delivering static content, should be consistent with crypto-proxy config, see `config_crypto-proxy.md`.
- `PUBLIC_KEY`: the public key paired with the private key used in crypto-proxy, see `config_crypto-proxy.md`.

Export public key with:
```
gpg --list-keys
gpg --armor --export <PUBLIC KEY ID>
```
