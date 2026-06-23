package zfscrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/go-encryptions/ccm"
)

// helper: build the same AEAD that Unwrap/DecryptBlock builds, so
// the tests can encrypt fixtures and round-trip them.
func aeadFor(t *testing.T, suite Suite, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	if suite.IsCCM() {
		aead, err := ccm.NewCCM(block, MACSize, IVSize)
		if err != nil {
			t.Fatalf("NewCCM: %v", err)
		}
		return aead
	}
	aead, err := cipher.NewGCMWithNonceSize(block, IVSize)
	if err != nil {
		t.Fatalf("NewGCMWithNonceSize: %v", err)
	}
	return aead
}

func TestSuiteMetadata(t *testing.T) {
	cases := []struct {
		s     Suite
		key   int
		isCCM bool
		label string
	}{
		{AES128CCM, 16, true, "aes-128-ccm"},
		{AES192CCM, 24, true, "aes-192-ccm"},
		{AES256CCM, 32, true, "aes-256-ccm"},
		{AES128GCM, 16, false, "aes-128-gcm"},
		{AES192GCM, 24, false, "aes-192-gcm"},
		{AES256GCM, 32, false, "aes-256-gcm"},
	}
	for _, c := range cases {
		if got := c.s.KeyLen(); got != c.key {
			t.Errorf("%s KeyLen = %d, want %d", c.s, got, c.key)
		}
		if got := c.s.IsCCM(); got != c.isCCM {
			t.Errorf("%s IsCCM = %v, want %v", c.s, got, c.isCCM)
		}
		if got := c.s.String(); got != c.label {
			t.Errorf("%s String = %q, want %q", c.s, got, c.label)
		}
	}
}

func TestDeriveWrappingKey(t *testing.T) {
	// PBKDF2-HMAC-SHA1 RFC 6070 vector #2 truncated to 20 bytes is
	// well-known, but we want 32 bytes; we cross-check our output
	// against a hand-computed expectation by simply re-deriving.
	k1, err := DeriveWrappingKey([]byte("password"), []byte("salt"), 4096)
	if err != nil {
		t.Fatalf("DeriveWrappingKey: %v", err)
	}
	if len(k1) != WrappingKeyLen {
		t.Fatalf("len = %d, want %d", len(k1), WrappingKeyLen)
	}
	// Deterministic: re-derive should match.
	k2, _ := DeriveWrappingKey([]byte("password"), []byte("salt"), 4096)
	if !bytes.Equal(k1, k2) {
		t.Errorf("DeriveWrappingKey not deterministic")
	}
	// Different iters → different key.
	k3, _ := DeriveWrappingKey([]byte("password"), []byte("salt"), 4097)
	if bytes.Equal(k1, k3) {
		t.Errorf("iters did not affect output")
	}

	// Reject iters <= 0.
	if _, err := DeriveWrappingKey([]byte("x"), []byte("s"), 0); err == nil {
		t.Errorf("iters=0 should be rejected")
	}
}

func TestUnwrapRoundTrip(t *testing.T) {
	// Cover both CCM and GCM, and both 128 and 256 bit suites.
	cases := []Suite{AES128CCM, AES256CCM, AES128GCM, AES256GCM}

	for _, suite := range cases {
		t.Run(suite.String(), func(t *testing.T) {
			// Simulate the wrap operation a pool performs at dataset-
			// create time: pick a wrapping key, IV, AD; encrypt the
			// 96-byte (32-byte MEK || 64-byte HMAC key) plaintext to
			// produce ciphertext + tag; then Unwrap with those inputs.
			wkey := makePattern(WrappingKeyLen, 0x10)
			mek := makePattern(MasterKeyLen, 0xa0)
			hkey := makePattern(HMACKeyLen, 0xb0)
			iv := makePattern(IVSize, 0x40)
			ad := []byte("dsl_crypto_key bonus fingerprint")

			// Synthesise wrap with the same AEAD Unwrap will use.
			// The wrapping key for OpenZFS is always AES-256-class,
			// so we use 32 bytes regardless of dataset suite — but
			// the dataset's suite still picks CCM vs GCM.
			aead := aeadFor(t, suite, wkey)
			pt := append([]byte{}, mek...)
			pt = append(pt, hkey...)
			sealed := aead.Seal(nil, iv, pt, ad)

			// Split into ciphertext || mac as ZFS stores them.
			ct := sealed[:WrappedKeySize]
			mac := sealed[WrappedKeySize:]

			gotMek, gotHkey, err := Unwrap(suite, wkey, iv, mac, ct, ad)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(gotMek, mek) {
				t.Errorf("MEK mismatch")
			}
			if !bytes.Equal(gotHkey, hkey) {
				t.Errorf("HMAC key mismatch")
			}

			// Tag-failure: flip one bit of the MAC.
			badMac := append([]byte{}, mac...)
			badMac[0] ^= 0x01
			if _, _, err := Unwrap(suite, wkey, iv, badMac, ct, ad); err == nil {
				t.Errorf("Unwrap accepted a corrupt MAC")
			}

			// AD-failure: change AD.
			if _, _, err := Unwrap(suite, wkey, iv, mac, ct, []byte("wrong AD")); err == nil {
				t.Errorf("Unwrap accepted wrong AD")
			}
		})
	}
}

func TestDeriveBlockKey(t *testing.T) {
	mek := makePattern(32, 0xa0)

	// Different salts → different keys.
	k1, err := DeriveBlockKey(AES256CCM, mek, []byte("salt-A"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	k2, _ := DeriveBlockKey(AES256CCM, mek, []byte("salt-B"))
	if bytes.Equal(k1, k2) {
		t.Errorf("different salts produced the same block key")
	}

	// OpenZFS binds ONLY the per-block salt into HKDF info (the HKDF
	// salt is empty); the suite is not part of the derivation. Two
	// 256-bit suites with the same salt therefore produce the SAME
	// 32-byte key — they differ only in the AEAD mode used downstream.
	kCCM, _ := DeriveBlockKey(AES256CCM, mek, []byte("salt"))
	kGCM, _ := DeriveBlockKey(AES256GCM, mek, []byte("salt"))
	if !bytes.Equal(kCCM, kGCM) {
		t.Errorf("AES256-CCM and AES256-GCM block keys differ — the suite must NOT be bound into HKDF (OpenZFS binds only the salt)")
	}

	// Length must match the suite.
	if got := len(kCCM); got != 32 {
		t.Errorf("AES256 block key len = %d, want 32", got)
	}
	k128, _ := DeriveBlockKey(AES128CCM, mek, []byte("salt"))
	if got := len(k128); got != 16 {
		t.Errorf("AES128 block key len = %d, want 16", got)
	}

	// MEK length is validated.
	if _, err := DeriveBlockKey(AES256CCM, []byte("short"), nil); err == nil {
		t.Errorf("DeriveBlockKey accepted a short MEK")
	}

	// Unknown suite is rejected.
	if _, err := DeriveBlockKey(SuiteInherit, mek, nil); err == nil {
		t.Errorf("DeriveBlockKey accepted Suite=Inherit")
	}
}

func TestDecryptBlockRoundTrip(t *testing.T) {
	for _, suite := range []Suite{AES256CCM, AES256GCM} {
		t.Run(suite.String(), func(t *testing.T) {
			mek := makePattern(32, 0xa0)
			blockKey, err := DeriveBlockKey(suite, mek, []byte("blocksalt"))
			if err != nil {
				t.Fatalf("DeriveBlockKey: %v", err)
			}
			iv := makePattern(IVSize, 0x60)
			ad := []byte("blkptr-fingerprint")
			plaintext := bytes.Repeat([]byte("the quick brown fox"), 256)

			aead := aeadFor(t, suite, blockKey)
			sealed := aead.Seal(nil, iv, plaintext, ad)
			ct := sealed[:len(plaintext)]
			mac := sealed[len(plaintext):]

			got, err := DecryptBlock(suite, blockKey, iv, mac, ct, ad)
			if err != nil {
				t.Fatalf("DecryptBlock: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("plaintext mismatch")
			}

			// Flip a byte in the ciphertext — must fail.
			ct[0] ^= 0x01
			if _, err := DecryptBlock(suite, blockKey, iv, mac, ct, ad); err == nil {
				t.Errorf("DecryptBlock accepted a tampered ciphertext")
			}
		})
	}
}

func TestHMACStable(t *testing.T) {
	hkey := makePattern(32, 0xb0)
	a := HMAC(hkey, []byte("hello"))
	b := HMAC(hkey, []byte("hello"))
	c := HMAC(hkey, []byte("world"))
	if !bytes.Equal(a, b) {
		t.Errorf("HMAC not deterministic")
	}
	if bytes.Equal(a, c) {
		t.Errorf("HMAC collided across different inputs")
	}
	if len(a) != 32 {
		t.Errorf("HMAC truncation wrong: got %d, want 32", len(a))
	}
}

// TestUnwrapInputValidation exercises every length/guard branch of
// Unwrap so a malformed DSL_CRYPTO_KEY surfaces a clear error rather
// than panicking or silently mis-slicing.
func TestUnwrapInputValidation(t *testing.T) {
	wkey := makePattern(WrappingKeyLen, 0x10)
	iv := makePattern(IVSize, 0x40)
	mac := makePattern(MACSize, 0x50)
	wrapped := makePattern(WrappedKeySize, 0x60)

	cases := []struct {
		name                string
		wkey, iv, mac, wrap []byte
	}{
		{"short wrapping key", wkey[:WrappingKeyLen-1], iv, mac, wrapped},
		{"short iv", wkey, iv[:IVSize-1], mac, wrapped},
		{"short mac", wkey, iv, mac[:MACSize-1], wrapped},
		{"short wrapped", wkey, iv, mac, wrapped[:WrappedKeySize-1]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := Unwrap(AES256GCM, c.wkey, c.iv, c.mac, c.wrap, nil); err == nil {
				t.Errorf("Unwrap accepted %s", c.name)
			}
		})
	}
}

// TestDecryptBlockInputValidation covers DecryptBlock's guard branches.
func TestDecryptBlockInputValidation(t *testing.T) {
	key := makePattern(32, 0x10) // AES256
	iv := makePattern(IVSize, 0x40)
	mac := makePattern(MACSize, 0x50)

	if _, err := DecryptBlock(AES256GCM, key[:31], iv, mac, nil, nil); err == nil {
		t.Errorf("accepted wrong key length")
	}
	if _, err := DecryptBlock(AES256GCM, key, iv[:IVSize-1], mac, nil, nil); err == nil {
		t.Errorf("accepted wrong iv length")
	}
	if _, err := DecryptBlock(AES256GCM, key, iv, mac[:MACSize-1], nil, nil); err == nil {
		t.Errorf("accepted wrong mac length")
	}
}

func makePattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	return out
}

// TestOpenZFSOracleVectors locks in real on-disk values captured from
// a genuine OpenZFS 2.2 encrypted pool (dataset created with
// `zfs create -o encryption=aes-256-gcm -o keyformat=passphrase`).
// The vectors were extracted with `zdb` from a file-vdev image and the
// full chain — PBKDF2 wrapping-key derivation, AES-256-GCM key unwrap,
// HKDF-SHA512 per-block key derivation, and AES-256-GCM block decrypt —
// reproduces the exact known plaintext written into the file.
//
// This is an end-to-end ORACLE test: unlike the round-trip tests above
// (which would pass for any self-consistent layout), it fails if any
// field length, AAD shape, or HKDF salt/info ordering drifts from what
// the OpenZFS userland actually wrote.
func TestOpenZFSOracleVectors(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("hex: %v", err)
		}
		return b
	}

	// ---- Wrapping-key derivation (PBKDF2-HMAC-SHA1) ----
	// passphrase "abcdefgh12345678", pbkdf2salt=5921960152581850962,
	// pbkdf2iters=350000. OpenZFS feeds the uint64 salt to PBKDF2 as
	// its 8-byte little-endian encoding.
	pass := []byte("abcdefgh12345678")
	saltLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltLE, 5921960152581850962) // pbkdf2salt
	wkey, err := DeriveWrappingKey(pass, saltLE, 350000)
	if err != nil {
		t.Fatalf("DeriveWrappingKey: %v", err)
	}
	wantWKey := mustHex("d088fb15db3ba339b2efade9b88a99ca64495442deb9a5f42e875bd175d6bcd5")
	if !bytes.Equal(wkey, wantWKey) {
		t.Fatalf("wrapping key:\n got  %x\n want %x", wkey, wantWKey)
	}

	// ---- Key unwrap (AES-256-GCM) ----
	// DSL_CRYPTO_KEY ZAP attributes from zdb.
	wrappedMEK := mustHex("934c1b7b54c8e091466937ac090763ef7d8d7c6d63e656783b560e739b987621")
	wrappedHMAC := mustHex("0d3ab829c1c530437144d7d3c930dd91f3f03b9985fcc9d91429b7d1375bc6dc" +
		"5e2962b73f51fc13a075fd0dd83005996b1aef3521b28e9c57d657a04fd88b9f")
	wrapIV := mustHex("8d3e7e31ca4a044651710672")
	wrapMAC := mustHex("348349e045fdb8d5212a486b6e07437b")
	wrapped := append(append([]byte{}, wrappedMEK...), wrappedHMAC...)
	if len(wrapped) != WrappedKeySize {
		t.Fatalf("wrapped blob = %d bytes, want %d", len(wrapped), WrappedKeySize)
	}

	// AAD for version-1 key: LE64(guid) || LE64(crypt) || LE64(version).
	// guid = -4635417775423895658 (signed) => 0xbfaf...; crypt = 8 (aes-256-gcm); version = 1.
	guid := uint64(0xBFABB017BE53C796) // two's-complement of -4635417775423895658
	ad := make([]byte, 24)
	binary.LittleEndian.PutUint64(ad[0:], guid)
	binary.LittleEndian.PutUint64(ad[8:], 8)
	binary.LittleEndian.PutUint64(ad[16:], 1)

	mek, hmacKey, err := Unwrap(AES256GCM, wkey, wrapIV, wrapMAC, wrapped, ad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	wantMEK := mustHex("068333f3e4b511cff3875c15df066367c4f8a2f9dfef0722ec2e63cb75675f8c")
	if !bytes.Equal(mek, wantMEK) {
		t.Fatalf("MEK:\n got  %x\n want %x", mek, wantMEK)
	}
	if len(hmacKey) != HMACKeyLen {
		t.Fatalf("HMAC key = %d bytes, want %d", len(hmacKey), HMACKeyLen)
	}

	// ---- Per-block key derivation (HKDF-SHA512, salt=empty, info=blk_salt) ----
	blkSalt := mustHex("f4c84b8f5ba994f1")
	blockKey, err := DeriveBlockKey(AES256GCM, mek, blkSalt)
	if err != nil {
		t.Fatalf("DeriveBlockKey: %v", err)
	}
	wantBK := mustHex("2dbc26e8e475305bcdb03ad7b94128a8e3503a7d31d956c3ff3294fa1649dbae")
	if !bytes.Equal(blockKey, wantBK) {
		t.Fatalf("block key:\n got  %x\n want %x", blockKey, wantBK)
	}

	// ---- Full block decrypt (AES-256-GCM) ----
	// Decrypt the real 4096-byte on-disk L0 data block (DVA 0:66000)
	// with the derived per-block key + the blkptr-resident IV/MAC and a
	// nil AAD (normal data blocks carry no AAD in OpenZFS). The GCM tag
	// only verifies if every field — key, IV, MAC, AAD — is correct, so
	// this is the strongest possible end-to-end assertion.
	ct, err := base64.StdEncoding.DecodeString(oracleCiphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	blkIV := mustHex("86aaf533f77fb83e20edfe74")
	blkMAC := mustHex("7fe245cdb07227e6d5a35e2352ac0089")
	pt, err := DecryptBlock(AES256GCM, blockKey, blkIV, blkMAC, ct, nil)
	if err != nil {
		t.Fatalf("DecryptBlock (real on-disk block): %v", err)
	}
	// The file was filled with the repeating pattern
	// "ZFSORACLEPATTERN0123456789ABCDEF"; it appears after the ZPL
	// system-attribute prefix of the first block.
	if !bytes.Contains(pt, []byte("ZFSORACLEPATTERN0123456789ABCDEF")) {
		t.Fatalf("decrypted block does not contain the known plaintext pattern; head=%x", pt[:48])
	}
}

// oracleCiphertext is the full 4096-byte L0 data block (DVA 0:66000)
// of the known file in the real aes-256-gcm test pool, base64-encoded.
// Decrypting it with the keys/fields derived above reproduces the known
// plaintext, validating the entire on-disk crypt layout end-to-end.
const oracleCiphertext = "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"
