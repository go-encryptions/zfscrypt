// Package zfscrypt implements the cryptographic primitives used by
// OpenZFS native (dataset-level) encryption, as added in OpenZFS 0.8
// (2019) and stable since.
//
// This package is the "math" half of ZFS encryption: KDF, MEK
// unwrap, per-block key derivation, AES-CCM/GCM block decryption.
// The "format" half — parsing the DSL_CRYPTO_KEY bonus area and
// extracting per-block IV/MAC from blkptr_t — lives in the
// pkg/go-filesystems/zfs driver, which already understands those
// on-disk structures.
//
// References (OpenZFS source tree):
//
//	module/zfs/zio_crypt.c
//	module/zfs/dsl_crypt.c
//	include/sys/zio_crypt.h
//	include/sys/dsl_crypt.h
//
// Only the read path is currently needed (cloud-boot just needs to
// pull /boot/vmlinuz + /boot/initrd out of an encrypted root), so
// Wrap and EncryptBlock are not exposed. Adding them later is
// straightforward — Seal is already there in the underlying AEADs.
//
// Algorithms covered:
//
//	AES-128/192/256-CCM (RFC 3610, via github.com/go-encryptions/ccm)
//	AES-128/192/256-GCM (stdlib crypto/cipher.NewGCM)
//
// Key derivation:
//
//	wrapping key  = PBKDF2-HMAC-SHA1(passphrase, salt, iters, 32)
//	per-block key = HKDF-SHA512(mek, salt=empty, info=blockSalt, KeyLen)
package zfscrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/go-encryptions/ccm"
	"github.com/go-encryptions/kdfbudget"
)

// Suite enumerates the encryption algorithms OpenZFS supports for
// dataset-level encryption.
//
// The numbers are this package's own compact numbering, NOT the on-disk
// value: OpenZFS stores a zio_crypt_type_t (include/sys/fs/zfs.h), where
// 1 is "on" and 2 is "off", so aes-128-ccm is 3 and aes-256-gcm is 8.
// Convert with SuiteFromZioCrypt and ZioCrypt; both are checked against
// pools written by OpenZFS (see testdata/openzfs.json).
type Suite uint8

// ZioCrypt returns the on-disk zio_crypt_type_t (the DSL_CRYPTO_SUITE
// value) for the suite, or 0 (ZIO_CRYPT_INHERIT) for a value that is not
// one of the six supported suites.
func (s Suite) ZioCrypt() uint64 {
	if s.KeyLen() == 0 {
		return 0
	}
	return uint64(s) + zioCryptOffset
}

// SuiteFromZioCrypt maps an on-disk zio_crypt_type_t to a Suite. ok is
// false for inherit, on, off (which name no algorithm by themselves) and
// anything out of range.
func SuiteFromZioCrypt(v uint64) (s Suite, ok bool) {
	if v < zioCryptOffset+uint64(AES128CCM) || v > zioCryptOffset+uint64(AES256GCM) {
		return SuiteInherit, false
	}
	return Suite(v - zioCryptOffset), true
}

// zioCryptOffset is ZIO_CRYPT_AES_128_CCM (3) minus AES128CCM (1).
const zioCryptOffset = 2

const (
	SuiteInherit  Suite = 0 // dataset inherits from parent (not used at the crypto layer)
	AES128CCM     Suite = 1
	AES192CCM     Suite = 2
	AES256CCM     Suite = 3
	AES128GCM     Suite = 4
	AES192GCM     Suite = 5
	AES256GCM     Suite = 6
	suiteFunction Suite = 7 // sentinel: out-of-range upper bound
)

// KeyLen returns the length, in bytes, of the data-encryption key
// for this suite.
func (s Suite) KeyLen() int {
	switch s {
	case AES128CCM, AES128GCM:
		return 16
	case AES192CCM, AES192GCM:
		return 24
	case AES256CCM, AES256GCM:
		return 32
	default:
		return 0
	}
}

// IsCCM reports whether the suite is CCM-mode (vs GCM-mode).
func (s Suite) IsCCM() bool {
	return s == AES128CCM || s == AES192CCM || s == AES256CCM
}

// String returns a stable label for logging.
func (s Suite) String() string {
	switch s {
	case AES128CCM:
		return "aes-128-ccm"
	case AES192CCM:
		return "aes-192-ccm"
	case AES256CCM:
		return "aes-256-ccm"
	case AES128GCM:
		return "aes-128-gcm"
	case AES192GCM:
		return "aes-192-gcm"
	case AES256GCM:
		return "aes-256-gcm"
	case SuiteInherit:
		return "inherit"
	default:
		return fmt.Sprintf("suite(%d)", uint8(s))
	}
}

// ZFS encryption uses 12-byte IVs and 16-byte MACs uniformly.
const (
	IVSize  = 12
	MACSize = 16
	// WrappingKeyLen is the length of the user-derived wrapping key
	// regardless of the dataset's data-encryption suite. OpenZFS
	// derives 32 bytes (WRAPPING_KEY_LEN); the AEAD that wraps the MEK
	// then wraps the MEK with all of it, for every suite (see Unwrap).
	WrappingKeyLen = 32
	// MasterKeyLen is MASTER_KEY_MAX_LEN in OpenZFS.
	MasterKeyLen = 32
	// HMACKeyLen is SHA512_HMAC_KEYLEN in OpenZFS — the wrapped HMAC
	// key is a full 64-byte HMAC-SHA512 key, NOT 32 bytes.
	HMACKeyLen = 64
	// WrappedKeySize is the size of the unwrap ciphertext input for the
	// 256-bit suites: master key (32) || HMAC key (64), decrypted as a
	// single AEAD ciphertext. The 128- and 192-bit suites carry a shorter
	// master key; see Suite.WrappedKeyLen.
	WrappedKeySize = MasterKeyLen + HMACKeyLen
)

// DeriveWrappingKey derives the dataset's wrapping key from the
// user passphrase via PBKDF2-HMAC-SHA1. The choice of SHA1 (rather
// than SHA512) matches what OpenZFS shipped in 0.8; do not
// "upgrade" without a corresponding on-disk format change.
//
// iters must match the value stored in the DSL_CRYPTO_KEY's
// `iters` field. Salt is the 8-byte field stored next to it.
//
// iters comes from an untrusted dataset header: the work is charged to a
// kdfbudget.Default budget first, so an absurd count is refused with
// ErrLimit before any hashing. OpenZFS has no upper bound; the default
// budget accepts every count up to 2^31. Use DeriveWrappingKeyBudget to
// choose the budget (kdfbudget.Unlimited for a trusted header).
//
// Output: WrappingKeyLen (32) bytes.
func DeriveWrappingKey(passphrase, salt []byte, iters int) ([]byte, error) {
	return DeriveWrappingKeyBudget(passphrase, salt, iters, kdfbudget.Default())
}

// ErrLimit is returned when the key derivation asks for more work than the
// budget allows. It is kdfbudget.ErrLimit.
var ErrLimit = kdfbudget.ErrLimit

// DeriveWrappingKeyBudget is DeriveWrappingKey with the caller's budget. The
// PBKDF2 run (one SHA-1 output block) is charged to b before it starts; a
// nil or zero Budget refuses.
func DeriveWrappingKeyBudget(passphrase, salt []byte, iters int, b *kdfbudget.Budget) ([]byte, error) {
	if iters <= 0 {
		return nil, errors.New("zfscrypt: iters must be positive")
	}
	if err := chargeIters(b, iters); err != nil {
		return nil, err
	}
	return pbkdf2.Key(sha1.New, string(passphrase), salt, iters, WrappingKeyLen)
}

// chargeIters charges one SHA-1 PBKDF2 output block of iters iterations to b.
// iters is checked positive first, so the uint64 conversion cannot wrap.
func chargeIters(b *kdfbudget.Budget, iters int) error {
	if iters <= 0 {
		return errors.New("zfscrypt: iters must be positive")
	}
	return b.ChargePBKDF2(kdfbudget.CostSHA1, uint64(iters))
}

// WrappedKeyLen is the length of the wrapped (MEK || HMAC key) ciphertext
// for the suite: KeyLen bytes of master key plus HMACKeyLen of HMAC key
// (96 for the 256-bit suites, 88 for 192, 80 for 128), or 0 for an
// unsupported suite.
func (s Suite) WrappedKeyLen() int {
	if s.KeyLen() == 0 {
		return 0
	}
	return s.KeyLen() + HMACKeyLen
}

// JoinWrappedKey builds the Unwrap input from the two byte arrays OpenZFS
// keeps in the DSL crypto key ZAP (DSL_CRYPTO_MASTER_KEY_1, always 32 bytes,
// and DSL_CRYPTO_HMAC_KEY_1, 64 bytes). For the 128- and 192-bit suites only
// the first KeyLen bytes of the master array are the wrapped key. The rest is
// padding whose content OpenZFS does not define (dsl_crypt.c leaves the
// buffer uninitialised, so it may be leftover stack), and is ignored.
func JoinWrappedKey(suite Suite, masterKey, hmacKey []byte) ([]byte, error) {
	if suite.KeyLen() == 0 {
		return nil, fmt.Errorf("zfscrypt: unsupported suite %s", suite)
	}
	if len(masterKey) != MasterKeyLen || len(hmacKey) != HMACKeyLen {
		return nil, fmt.Errorf("zfscrypt: master key must be %d bytes and HMAC key %d, got %d and %d",
			MasterKeyLen, HMACKeyLen, len(masterKey), len(hmacKey))
	}
	out := make([]byte, 0, suite.WrappedKeyLen())
	out = append(out, masterKey[:suite.KeyLen()]...)
	return append(out, hmacKey...), nil
}

// Unwrap decrypts a wrapped (MEK || HMAC key) blob using the
// dataset's wrapping key.
//
// suite chooses the AEAD: CCM or GCM. iv is the 12-byte field
// stored in the DSL_CRYPTO_KEY object; mac is the matching 16-byte
// authentication tag; wrapped is the suite.WrappedKeyLen() byte
// ciphertext (master key of suite.KeyLen() bytes || 64-byte HMAC key);
// JoinWrappedKey builds it from the on-disk ZAP values.
//
// ad is the additional authenticated data the pool computed at
// wrap time. OpenZFS zio_crypt_key_unwrap() uses LE64(guid) for
// version-0 keys, and LE64(guid)||LE64(crypt)||LE64(version) for
// the current version. The caller must pass the same bytes the
// pool used; passing the wrong AD shows up as a tag-verification
// failure rather than as decryption garbage.
//
// Returns the MEK (suite.KeyLen() bytes: 16, 24 or 32, as OpenZFS keeps
// it) and the 64-byte HMAC key on success.
func Unwrap(suite Suite, wrappingKey, iv, mac, wrapped, ad []byte) (mek, hmacKey []byte, err error) {
	if len(wrappingKey) != WrappingKeyLen {
		return nil, nil, fmt.Errorf("zfscrypt: wrapping key must be %d bytes, got %d", WrappingKeyLen, len(wrappingKey))
	}
	if len(iv) != IVSize {
		return nil, nil, fmt.Errorf("zfscrypt: iv must be %d bytes, got %d", IVSize, len(iv))
	}
	if len(mac) != MACSize {
		return nil, nil, fmt.Errorf("zfscrypt: mac must be %d bytes, got %d", MACSize, len(mac))
	}
	if suite.KeyLen() == 0 {
		return nil, nil, fmt.Errorf("zfscrypt: unwrap: unsupported suite %s", suite)
	}
	if want := suite.WrappedKeyLen(); len(wrapped) != want {
		return nil, nil, fmt.Errorf("zfscrypt: wrapped blob for %s must be %d bytes, got %d", suite, want, len(wrapped))
	}

	// The wrapping key is the full 32 bytes for every suite, so the 128-
	// and 192-bit suites wrap with AES-256 (verified against OpenZFS).
	pt, err := decryptAEAD(suite, wrappingKey, iv, mac, wrapped, ad)
	if err != nil {
		return nil, nil, fmt.Errorf("zfscrypt: unwrap: %w", err)
	}
	return pt[:suite.KeyLen()], pt[suite.KeyLen():], nil
}

// DeriveBlockKey derives the per-block data-encryption key from the
// dataset's master encryption key via HKDF-SHA512.
//
// CONFIRMED against OpenZFS (zfs-2.2.x sources; judged on kmod 2.3.4): module/os/*/zfs/zio_crypt.c
// zio_do_crypt_data() derives the per-block key with
//
//	hkdf_sha512(master, keylen, /*salt*/ NULL, 0,
//	            /*info*/ blk_salt, ZIO_DATA_SALT_LEN, out, keylen)
//
// where hkdf_sha512's prototype is
//
//	hkdf_sha512(key_material, km_len, salt, salt_len, info, info_len, out, out_len)
//
// — i.e. the HKDF *salt* is EMPTY and the per-block 8-byte salt is the
// HKDF *info*. (This is the opposite of the intuitive "salt is the
// salt" mapping; an earlier version of this function used the block
// salt as the HKDF salt and the suite name as info, which produced a
// key that did NOT decrypt real on-disk blocks.) Validated end-to-end
// against a real aes-256-gcm pool: the key produced here, with the
// block IV/MAC from the blkptr, decrypts on-disk ciphertext and the
// GCM tag verifies.
//
// The `salt` argument is the encrypted block's BP_CRYPT salt
// (ZIO_DATA_SALT_LEN = 8 bytes). Output length matches the suite's
// data-key length (16/24/32).
func DeriveBlockKey(suite Suite, mek, salt []byte) ([]byte, error) {
	klen := suite.KeyLen()
	if klen == 0 {
		return nil, fmt.Errorf("zfscrypt: unknown suite %s", suite)
	}
	if len(mek) != klen {
		return nil, fmt.Errorf("zfscrypt: mek for %s must be %d bytes, got %d", suite, klen, len(mek))
	}
	// HKDF salt = empty; HKDF info = the per-block salt bytes.
	return hkdf.Key(sha512.New, mek, nil, string(salt), klen)
}

// DecryptBlock authenticates and decrypts one encrypted ZFS block
// using a previously-derived per-block key. iv is the block's IV
// (12 bytes), mac is the block's authentication tag (16 bytes),
// ciphertext is the raw block payload (without IV/MAC appended),
// and ad is the additional authenticated data the pool computed
// over the blkptr's "sensitive" fields (blockid, logical birth
// txg, …).
//
// Returns the plaintext or an error on tag-verification failure.
func DecryptBlock(suite Suite, key, iv, mac, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != suite.KeyLen() {
		return nil, fmt.Errorf("zfscrypt: key length %d does not match %s", len(key), suite)
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("zfscrypt: iv must be %d bytes", IVSize)
	}
	if len(mac) != MACSize {
		return nil, fmt.Errorf("zfscrypt: mac must be %d bytes", MACSize)
	}
	return decryptAEAD(suite, key, iv, mac, ciphertext, ad)
}

// HMAC returns HMAC-SHA512-256 over data using the dataset's HMAC
// key (the 64-byte sibling of the MEK obtained from Unwrap).
// OpenZFS uses this to authenticate metadata that does not pass
// through the AEAD layer — most notably the per-block "salt"
// field. The truncation to 32 bytes matches OpenZFS's choice.
func HMAC(hmacKey, data []byte) []byte {
	mac := hmac.New(sha512.New, hmacKey)
	mac.Write(data)
	sum := mac.Sum(nil)
	return sum[:32]
}

// decryptAEAD is the inner helper: build the right AEAD instance
// for `suite`, then Open(ciphertext || mac) with the given AD.
func decryptAEAD(suite Suite, key, iv, mac, ciphertext, ad []byte) ([]byte, error) {
	// An unknown suite must not fall through to GCM: Unwrap(0, ...) or
	// Unwrap(99, ...) would otherwise "succeed" as AES-GCM.
	if suite.KeyLen() == 0 {
		return nil, fmt.Errorf("unsupported suite %s", suite)
	}
	block, err := newBlock(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}

	var aead cipher.AEAD
	if suite.IsCCM() {
		aead, err = newCCM(block, MACSize, IVSize)
	} else {
		aead, err = newGCM(block, IVSize)
	}
	if err != nil {
		return nil, fmt.Errorf("AEAD ctor (%s): %w", suite, err)
	}

	// AEAD interfaces want ciphertext || tag concatenated. ZFS
	// stores tag separately in the blkptr, so we splice them back
	// together for Open.
	buf := make([]byte, 0, len(ciphertext)+len(mac))
	buf = append(buf, ciphertext...)
	buf = append(buf, mac...)

	return aead.Open(nil, iv, buf, ad)
}

// The AEAD constructors, as variables only so a test can prove that a
// constructor failure is reported and not swallowed. With the constant
// 12-byte nonce and 16-byte tag used here neither can fail.
var (
	newBlock = aes.NewCipher
	newCCM   = ccm.NewCCM
	newGCM   = cipher.NewGCMWithNonceSize
)
