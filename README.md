<p align="center"><img src="https://raw.githubusercontent.com/go-encryptions/brand/main/social/go-encryptions.png" alt="go-encryptions/zfscrypt" width="720"></p>

# go-encryptions/zfscrypt

[![ci](https://github.com/go-encryptions/zfscrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/go-encryptions/zfscrypt/actions/workflows/ci.yml)

Pure-Go cryptographic primitives for **OpenZFS native (dataset-level) encryption** — the key hierarchy and block decryption needed to read an encrypted ZFS dataset without libzfs or cgo. Part of the [`go-encryptions`](https://github.com/go-encryptions) family; AES-CCM is provided by [`go-encryptions/ccm`](https://github.com/go-encryptions/ccm) and AES-GCM by the standard library.

This is the crypto layer only (KDF → wrapping key → MEK unwrap → per-block key → block decrypt). It does not parse the ZFS on-disk format; pair it with a DMU/DSL reader that supplies the salts, IVs, MACs and ciphertext.

## Install

```sh
go get github.com/go-encryptions/zfscrypt
```

## Suites

`Suite` mirrors the on-disk `crypt_algorithm` field of a `DSL_CRYPTO_KEY` object:

| `Suite` | value | key length |
| --- | --- | --- |
| `AES128CCM` / `AES128GCM` | 1 / 4 | 16 bytes |
| `AES192CCM` / `AES192GCM` | 2 / 5 | 24 bytes |
| `AES256CCM` / `AES256GCM` | 3 / 6 | 32 bytes |

## Key hierarchy

```go
// 1. passphrase → wrapping key (PBKDF2-HMAC-SHA1, per the OpenZFS user-key format)
wk, _ := zfscrypt.DeriveWrappingKey(passphrase, salt, iters)

// 2. unwrap the master encryption key (MEK) + HMAC key from the DSL_CRYPTO_KEY
mek, hmacKey, err := zfscrypt.Unwrap(suite, wk, iv, mac, wrapped, ad)

// 3. derive the per-block key, then decrypt one block
blockKey, _ := zfscrypt.DeriveBlockKey(suite, mek, blockSalt)
plain, err := zfscrypt.DecryptBlock(suite, blockKey, blockIV, blockMAC, ciphertext, ad)
```

`HMAC(hmacKey, data)` exposes the keyed digest used for object-level integrity.

## Security notes

- **SHA-1 in `DeriveWrappingKey`** is *mandated by the OpenZFS 0.8 user-key format* (PBKDF2-HMAC-SHA1) — it is not a strength choice and must not be changed, or existing datasets become undecryptable. Documented inline.
- All AEAD operations go through authenticated `Open()`; key material is sliced out only after the tag verifies.
- Length parameters are validated before use; no `unsafe`, no cgo.

## License

BSD-3-Clause © the go-encryptions/zfscrypt authors.
