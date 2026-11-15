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

`Suite` is this package's own compact numbering, **not** the on-disk value: OpenZFS stores a `zio_crypt_type_t`, where 1 is `on` and 2 is `off`. Convert with `SuiteFromZioCrypt` / `Suite.ZioCrypt`.

| `Suite` | value | on disk (`DSL_CRYPTO_SUITE`) | key length |
| --- | --- | --- | --- |
| `AES128CCM` / `AES128GCM` | 1 / 4 | 3 / 6 | 16 bytes |
| `AES192CCM` / `AES192GCM` | 2 / 5 | 4 / 7 | 24 bytes |
| `AES256CCM` / `AES256GCM` | 3 / 6 | 5 / 8 | 32 bytes |

The master encryption key is `KeyLen` bytes long (16, 24 or 32), as OpenZFS keeps it; the wrapping key is always 32 bytes.

## Key hierarchy

```go
// 1. passphrase → wrapping key (PBKDF2-HMAC-SHA1, per the OpenZFS user-key format)
wk, _ := zfscrypt.DeriveWrappingKey(passphrase, salt, iters)

// 2. unwrap the master encryption key (MEK) + HMAC key from the DSL_CRYPTO_KEY.
//    JoinWrappedKey builds the blob from the DSL_CRYPTO_MASTER_KEY_1 (32 bytes,
//    only the first KeyLen bytes count for the 128/192-bit suites) and DSL_CRYPTO_HMAC_KEY_1 arrays;
//    ad = LE64(guid) || LE64(DSL_CRYPTO_SUITE) || LE64(version).
wrapped, _ := zfscrypt.JoinWrappedKey(suite, masterKeyArray, hmacKeyArray)
mek, hmacKey, err := zfscrypt.Unwrap(suite, wk, iv, mac, wrapped, ad)

// 3. derive the per-block key, then decrypt one block
blockKey, _ := zfscrypt.DeriveBlockKey(suite, mek, blockSalt)
plain, err := zfscrypt.DecryptBlock(suite, blockKey, blockIV, blockMAC, ciphertext, ad)
```

`HMAC(hmacKey, data)` exposes the keyed digest used for object-level integrity.

## Verified against OpenZFS

`testdata/openzfs.json` was written by OpenZFS itself, not by this package: `tools/zfsjudge` (a separate module) runs as root on a Linux host, creates a file-backed pool, one passphrase-encrypted dataset for each of the six suites (`zfs create -o encryption=<suite> -o keyformat=passphrase`, the passphrase read from a file), writes a known two-block file into each, exports the pool, and records with `zdb` the wrapped keys, IV, MAC, GUID, version, PBKDF2 salt and iterations, and each data block's salt, IV and MAC, plus the raw ciphertext from the image. The tests derive the key, unwrap the master key and decrypt every block and demand the plaintext that was written, for all six suites, and check that corrupting the ciphertext, MAC, IV, AAD, wrapping AD, passphrase or suite is refused.

`ZFSCRYPT_FIXTURES=<file>` points the same tests at a freshly generated file (the live run).

## Limitations

- **Decrypt only.** There is no wrap or encrypt path.
- **Tested against one OpenZFS build:** user tools zfs-2.2.2 (Ubuntu 24.04, `zfs-2.2.2-0ubuntu9.5`) with kernel module 2.3.4 (`zfs-kmod-2.3.4-1ubuntu2`, Linux 6.17, arm64), key version 1, passphrase keys (`keyformat=passphrase`, `pbkdf2iters=100000`), `compression=off`, 4 KiB records. Raw-key (`keyformat=raw`/`hex`) datasets use no PBKDF2 and were not exercised.
- **Only plain file data blocks were judged.** `DecryptBlock` takes the additional data you give it; for data blocks that is empty. The AAD OpenZFS builds for dnode and objset blocks is the caller's job, and no such block was verified.
- **`HMAC` is not verified by OpenZFS.** The unwrapped HMAC key is checked only in that it authenticates as part of the wrapped blob; the keyed digest over objset data was not compared with OpenZFS output.
- **Key version 0 datasets** (AD = `LE64(guid)` only) were not generated; the caller builds the AD.
- **No external audit.** The cryptography is the standard library's (AES, GCM, PBKDF2, HKDF, HMAC) plus `go-encryptions/ccm`; this package only assembles OpenZFS's key hierarchy, and nobody outside the project has reviewed that assembly.
- **PBKDF2-HMAC-SHA1 is mandated** by the format (see below).

## Security notes

- **SHA-1 in `DeriveWrappingKey`** is *mandated by the OpenZFS 0.8 user-key format* (PBKDF2-HMAC-SHA1) — it is not a strength choice and must not be changed, or existing datasets become undecryptable. Documented inline.
- All AEAD operations go through authenticated `Open()`; key material is sliced out only after the tag verifies.
- Length parameters are validated before use; no `unsafe`, no cgo.

## License

BSD-3-Clause © the go-encryptions/zfscrypt authors.
