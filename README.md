# globaloe

a plugin for encrypting obsidian notes in-memory, password based.

## spec

cryptographic algorithms were chosen conservately.

- extension: aes256
- format: markdown
- key derivation: pbkdf2-sha512 with 1000000 iters
- mode of operation: aes256-gcm aead (auth + encryption)

