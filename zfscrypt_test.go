package zfscrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
		s      Suite
		key    int
		isCCM  bool
		label  string
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
			// 64-byte (MEK || HMAC key) plaintext to produce ciphertext
			// + tag; then Unwrap with those exact inputs.
			wkey := makePattern(WrappingKeyLen, 0x10)
			mek := makePattern(32, 0xa0)
			hkey := makePattern(32, 0xb0)
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

	// Suite labels are bound into HKDF info, so CCM and GCM keys diverge.
	kCCM, _ := DeriveBlockKey(AES256CCM, mek, []byte("salt"))
	kGCM, _ := DeriveBlockKey(AES256GCM, mek, []byte("salt"))
	if bytes.Equal(kCCM, kGCM) {
		t.Errorf("AES256-CCM and AES256-GCM block keys collided — info binding broken")
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

func makePattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	return out
}
