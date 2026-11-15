package zfscrypt

import (
	"bytes"
	"testing"
)

// FuzzInputs throws arbitrary field bytes at every entry point. None may
// panic, and when a decryption does authenticate, re-sealing the plaintext
// with the same key, IV and AD must reproduce ciphertext and tag exactly
// (an AEAD is deterministic), so "accepted" always means "genuinely valid".
func FuzzInputs(f *testing.F) {
	f.Add(uint8(AES256GCM), makePattern(32, 1), makePattern(12, 2), makePattern(16, 3), makePattern(96, 4), []byte("ad"))
	f.Add(uint8(AES128CCM), makePattern(16, 1), makePattern(12, 2), makePattern(16, 3), makePattern(4096, 4), []byte(nil))
	f.Add(uint8(0), []byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil))
	f.Add(uint8(255), makePattern(33, 9), makePattern(13, 9), makePattern(17, 9), makePattern(80, 9), makePattern(24, 9))

	f.Fuzz(func(t *testing.T, s uint8, key, iv, mac, data, ad []byte) {
		suite := Suite(s)
		if v, ok := SuiteFromZioCrypt(uint64(s)); ok && v.ZioCrypt() != uint64(s) {
			t.Fatalf("zio_crypt %d -> %v -> %d", s, v, v.ZioCrypt())
		}
		_, _ = JoinWrappedKey(suite, key, data)
		_, _ = DeriveBlockKey(suite, key, data)
		_, _ = DeriveWrappingKey(key, data, int(s)%3)
		_ = HMAC(key, data)
		_, _, _ = Unwrap(suite, key, iv, mac, data, ad)

		pt, err := DecryptBlock(suite, key, iv, mac, data, ad)
		if err != nil {
			return
		}
		sealed := aeadFor(t, suite, key).Seal(nil, iv, pt, ad)
		if !bytes.Equal(sealed[:len(pt)], data) || !bytes.Equal(sealed[len(pt):], mac) {
			t.Fatalf("accepted a block that does not re-encrypt to itself")
		}
	})
}
