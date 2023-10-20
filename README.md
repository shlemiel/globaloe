# global-markdown-encrypt

a plugin for encrypting obsidian markdowns in-memory, single password based.

## spec

cryptographic algorithms were chosen conservately.

- key derivation: pbkdf2-sha512 with 1000000 iters
- mode of operation: aes256-gcm aead (auth + encryption)
- file extension: aes256
