package zfscrypt

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

// The OpenZFS judge.
//
// testdata/openzfs.json was written by real OpenZFS (tools/zfsjudge, run as
// root in a Linux VM: zpool create on a file, one `zfs create -o
// encryption=<suite> -o keyformat=passphrase` dataset per suite, a known
// two-block file in each, pool exported, then zdb and the raw image read
// back). Nothing in it comes from this package. Every test below feeds those
// fields through zfscrypt and demands the plaintext OpenZFS was given.
//
// ZFSCRYPT_FIXTURES=<file> points the same tests at a freshly generated file
// (the live VM run); without it the committed fixtures are used.

type judgeBlock struct {
	Index      int    `json:"index"`
	Salt       []byte `json:"salt"`
	IV         []byte `json:"iv"`
	MAC        []byte `json:"mac"`
	Ciphertext []byte `json:"ciphertext"`
	Plaintext  []byte `json:"plaintext"`
}

type judgeFixture struct {
	Suite       string       `json:"suite"`
	Crypt       uint64       `json:"crypt"`
	Version     uint64       `json:"version"`
	GUID        uint64       `json:"guid"`
	Passphrase  string       `json:"passphrase"`
	PBKDF2Salt  []byte       `json:"pbkdf2salt"`
	PBKDF2Iters int          `json:"pbkdf2iters"`
	IV          []byte       `json:"iv"`
	MAC         []byte       `json:"mac"`
	MasterKey   []byte       `json:"wrapped_master_key"`
	HMACKey     []byte       `json:"wrapped_hmac_key"`
	Blocks      []judgeBlock `json:"blocks"`
}

type judgeFile struct {
	ZFS      string         `json:"zfs_version"`
	Kernel   string         `json:"kernel"`
	Fixtures []judgeFixture `json:"fixtures"`
}

func loadJudge(t *testing.T) judgeFile {
	t.Helper()
	path := "testdata/openzfs.json"
	if p := os.Getenv("ZFSCRYPT_FIXTURES"); p != "" {
		path = p
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var f judgeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

// suiteByName is the suite each OpenZFS `encryption` property value must be.
var suiteByName = map[string]Suite{
	"aes-128-ccm": AES128CCM, "aes-192-ccm": AES192CCM, "aes-256-ccm": AES256CCM,
	"aes-128-gcm": AES128GCM, "aes-192-gcm": AES192GCM, "aes-256-gcm": AES256GCM,
}

// wantPlain is the plaintext the judge wrote, rebuilt here independently of
// the fixture: readable text repeated to the 4096-byte block.
func wantPlain(suite string, i int) []byte {
	unit := []byte(fmt.Sprintf("zfscrypt openzfs judge | %s | block %d | ", suite, i))
	return bytes.Repeat(unit, 4096/len(unit)+1)[:4096]
}

func unwrapAD(fx judgeFixture) []byte {
	ad := make([]byte, 24)
	binary.LittleEndian.PutUint64(ad[0:], fx.GUID)
	binary.LittleEndian.PutUint64(ad[8:], fx.Crypt)
	binary.LittleEndian.PutUint64(ad[16:], fx.Version)
	return ad
}

// wrappedBlob is the Unwrap input, built from the ZAP arrays OpenZFS wrote.
func wrappedBlob(fx judgeFixture) []byte {
	b, err := JoinWrappedKey(suiteByName[fx.Suite], fx.MasterKey, fx.HMACKey)
	if err != nil {
		panic(err)
	}
	return b
}

func TestJudgeCoversEverySuite(t *testing.T) {
	f := loadJudge(t)
	if f.ZFS == "" || f.Kernel == "" {
		t.Errorf("fixtures do not record the OpenZFS version (%q) and kernel (%q)", f.ZFS, f.Kernel)
	}
	seen := map[string]bool{}
	for _, fx := range f.Fixtures {
		seen[fx.Suite] = true
	}
	for name := range suiteByName {
		if !seen[name] {
			t.Errorf("no OpenZFS fixture for %s", name)
		}
	}
	if len(f.Fixtures) != len(suiteByName) {
		t.Errorf("%d fixtures, want %d", len(f.Fixtures), len(suiteByName))
	}
}

func TestOpenZFSJudge(t *testing.T) {
	for _, fx := range loadJudge(t).Fixtures {
		t.Run(fx.Suite, func(t *testing.T) {
			suite, ok := suiteByName[fx.Suite]
			if !ok {
				t.Fatalf("unknown suite %q in fixtures", fx.Suite)
			}

			// OpenZFS's on-disk value maps to the same suite, both ways.
			got, ok := SuiteFromZioCrypt(fx.Crypt)
			if !ok || got != suite {
				t.Fatalf("SuiteFromZioCrypt(%d) = %v, %v; want %v", fx.Crypt, got, ok, suite)
			}
			if suite.ZioCrypt() != fx.Crypt {
				t.Fatalf("%s.ZioCrypt() = %d; OpenZFS wrote %d", suite, suite.ZioCrypt(), fx.Crypt)
			}

			wk, err := DeriveWrappingKey([]byte(fx.Passphrase), fx.PBKDF2Salt, fx.PBKDF2Iters)
			if err != nil {
				t.Fatal(err)
			}
			mek, hmacKey, err := Unwrap(suite, wk, fx.IV, fx.MAC, wrappedBlob(fx), unwrapAD(fx))
			if err != nil {
				t.Fatalf("OpenZFS's own wrapped key does not unwrap: %v", err)
			}
			if len(mek) != suite.KeyLen() || len(hmacKey) != HMACKeyLen {
				t.Fatalf("key sizes %d/%d, want %d/%d", len(mek), len(hmacKey), suite.KeyLen(), HMACKeyLen)
			}

			if len(fx.Blocks) < 2 {
				t.Fatalf("%d blocks, want at least 2", len(fx.Blocks))
			}
			for _, b := range fx.Blocks {
				key, err := DeriveBlockKey(suite, mek, b.Salt)
				if err != nil {
					t.Fatal(err)
				}
				pt, err := DecryptBlock(suite, key, b.IV, b.MAC, b.Ciphertext, nil)
				if err != nil {
					t.Fatalf("block %d does not authenticate: %v", b.Index, err)
				}
				if !bytes.Equal(pt, b.Plaintext) {
					t.Fatalf("block %d: plaintext differs from what the fixture recorded", b.Index)
				}
				if !bytes.Equal(pt, wantPlain(fx.Suite, b.Index)) {
					t.Fatalf("block %d: plaintext is not what was written to the dataset", b.Index)
				}
				if bytes.Equal(b.Ciphertext, pt) {
					t.Fatalf("block %d: ciphertext equals plaintext; nothing was encrypted", b.Index)
				}

				// Authentication really is checked: every field matters.
				flip := func(p []byte) []byte { q := bytes.Clone(p); q[0] ^= 1; return q }
				if _, err := DecryptBlock(suite, key, b.IV, b.MAC, flip(b.Ciphertext), nil); err == nil {
					t.Errorf("block %d: flipped ciphertext bit accepted", b.Index)
				}
				if _, err := DecryptBlock(suite, key, b.IV, flip(b.MAC), b.Ciphertext, nil); err == nil {
					t.Errorf("block %d: flipped MAC bit accepted", b.Index)
				}
				if _, err := DecryptBlock(suite, key, flip(b.IV), b.MAC, b.Ciphertext, nil); err == nil {
					t.Errorf("block %d: flipped IV bit accepted", b.Index)
				}
				if _, err := DecryptBlock(suite, key, b.IV, b.MAC, b.Ciphertext, []byte{0}); err == nil {
					t.Errorf("block %d: unexpected AAD accepted", b.Index)
				}
				// A key derived from a different salt must not decrypt it.
				other, _ := DeriveBlockKey(suite, mek, flip(b.Salt))
				if _, err := DecryptBlock(suite, other, b.IV, b.MAC, b.Ciphertext, nil); err == nil {
					t.Errorf("block %d: key from another salt decrypted it", b.Index)
				}
			}

			// Unwrap authenticates the key blob and its AD.
			if _, _, err := Unwrap(suite, wk, fx.IV, fx.MAC, wrappedBlob(fx), nil); err == nil {
				t.Error("Unwrap accepted without the AD OpenZFS bound the key to")
			}
			badAD := unwrapAD(fx)
			badAD[16] ^= 1 // version
			if _, _, err := Unwrap(suite, wk, fx.IV, fx.MAC, wrappedBlob(fx), badAD); err == nil {
				t.Error("Unwrap accepted a wrong version in the AD")
			}
			wrong, _ := DeriveWrappingKey([]byte(fx.Passphrase+"x"), fx.PBKDF2Salt, fx.PBKDF2Iters)
			if _, _, err := Unwrap(suite, wrong, fx.IV, fx.MAC, wrappedBlob(fx), unwrapAD(fx)); err == nil {
				t.Error("Unwrap accepted a wrong passphrase")
			}
			// A suite of the other mode does not unwrap it either.
			// (same key length, so only the AEAD differs, not the length check).
			other := suite - 3
			if suite.IsCCM() {
				other = suite + 3
			}
			if other.KeyLen() != suite.KeyLen() || other.IsCCM() == suite.IsCCM() {
				t.Fatalf("test bug: %s vs %s", suite, other)
			}
			if _, _, err := Unwrap(other, wk, fx.IV, fx.MAC, wrappedBlob(fx), unwrapAD(fx)); err == nil {
				t.Error("Unwrap accepted the key under the other AEAD mode")
			}
			// The AD binds the on-disk crypt value too.
			badCrypt := unwrapAD(fx)
			badCrypt[8] ^= 1
			if _, _, err := Unwrap(suite, wk, fx.IV, fx.MAC, wrappedBlob(fx), badCrypt); err == nil {
				t.Error("Unwrap accepted a wrong crypt value in the AD")
			}
		})
	}
}

// For the 128- and 192-bit suites OpenZFS keeps a master key of only KeyLen
// bytes (the ZAP array is padded to 32 with undefined content) and still wraps
// it with the full 32-byte wrapping key. The judge's blobs prove both; the
// padding is ignored by JoinWrappedKey.
func TestJoinWrappedKeyOnOpenZFSArrays(t *testing.T) {
	for _, fx := range loadJudge(t).Fixtures {
		suite := suiteByName[fx.Suite]
		if len(fx.MasterKey) != MasterKeyLen || len(fx.HMACKey) != HMACKeyLen {
			t.Fatalf("%s: ZAP arrays are %d/%d bytes", fx.Suite, len(fx.MasterKey), len(fx.HMACKey))
		}
		blob, err := JoinWrappedKey(suite, fx.MasterKey, fx.HMACKey)
		if err != nil {
			t.Fatalf("%s: %v", fx.Suite, err)
		}
		if len(blob) != suite.WrappedKeyLen() {
			t.Fatalf("%s: blob %d bytes, want %d", fx.Suite, len(blob), suite.WrappedKeyLen())
		}
		if !bytes.Equal(blob[:suite.KeyLen()], fx.MasterKey[:suite.KeyLen()]) || !bytes.Equal(blob[suite.KeyLen():], fx.HMACKey) {
			t.Fatalf("%s: blob is not master[:KeyLen] || hmac", fx.Suite)
		}
		// Joining as if it were a 256-bit suite would feed the pad to the AEAD
		// and fail authentication: the layout matters, not just the length.
		if suite.KeyLen() < MasterKeyLen {
			wk, _ := DeriveWrappingKey([]byte(fx.Passphrase), fx.PBKDF2Salt, fx.PBKDF2Iters)
			padded := append(bytes.Clone(fx.MasterKey), fx.HMACKey...)
			a := aeadFor(t, suite, wk)
			if _, err := a.Open(nil, fx.IV, append(padded, fx.MAC...), unwrapAD(fx)); err == nil {
				t.Fatalf("%s: the padded 96-byte layout authenticates; the layout claim is false", fx.Suite)
			}
		}
	}
}

func TestJoinWrappedKeyRejects(t *testing.T) {
	m, h := make([]byte, MasterKeyLen), make([]byte, HMACKeyLen)
	if _, err := JoinWrappedKey(SuiteInherit, m, h); err == nil {
		t.Error("unsupported suite accepted")
	}
	if _, err := JoinWrappedKey(AES128GCM, m[:31], h); err == nil {
		t.Error("short master array accepted")
	}
	if _, err := JoinWrappedKey(AES128GCM, m, h[:63]); err == nil {
		t.Error("short HMAC array accepted")
	}
	// Padding content is undefined in OpenZFS: it must not change the blob
	// for a 128-bit suite, and is key material for a 256-bit one.
	a, _ := JoinWrappedKey(AES128GCM, m, h)
	m[20] = 0xEE
	b, err := JoinWrappedKey(AES128GCM, m, h)
	if err != nil || !bytes.Equal(a, b) {
		t.Errorf("padding changed the 128-bit blob (err %v)", err)
	}
	c, err := JoinWrappedKey(AES256GCM, m, h)
	if err != nil || c[20] != 0xEE {
		t.Errorf("256-bit suite lost byte 20: %v", err)
	}
	if AES192CCM.WrappedKeyLen() != 88 || AES128GCM.WrappedKeyLen() != 80 || AES256CCM.WrappedKeyLen() != WrappedKeySize || SuiteInherit.WrappedKeyLen() != 0 {
		t.Error("WrappedKeyLen wrong")
	}
}

func TestUnwrapChecksWrappedLengthPerSuite(t *testing.T) {
	wk, iv, mac := makePattern(WrappingKeyLen, 1), makePattern(IVSize, 2), makePattern(MACSize, 3)
	// 96 bytes is right for a 256-bit suite and wrong for a 128-bit one.
	if _, _, err := Unwrap(AES128GCM, wk, iv, mac, makePattern(WrappedKeySize, 4), nil); err == nil {
		t.Error("96-byte blob accepted for aes-128-gcm")
	}
	if _, _, err := Unwrap(AES256GCM, wk, iv, mac, makePattern(80, 4), nil); err == nil {
		t.Error("80-byte blob accepted for aes-256-gcm")
	}
}

func TestSuiteZioCryptMapping(t *testing.T) {
	all := []struct {
		s Suite
		v uint64
	}{
		{AES128CCM, 3}, {AES192CCM, 4}, {AES256CCM, 5},
		{AES128GCM, 6}, {AES192GCM, 7}, {AES256GCM, 8},
	}
	for _, c := range all {
		if got := c.s.ZioCrypt(); got != c.v {
			t.Errorf("%s.ZioCrypt() = %d, want %d", c.s, got, c.v)
		}
		if s, ok := SuiteFromZioCrypt(c.v); !ok || s != c.s {
			t.Errorf("SuiteFromZioCrypt(%d) = %v, %v; want %v", c.v, s, ok, c.s)
		}
	}
	// inherit(0), on(1), off(2), functions(9) and beyond name no algorithm.
	for _, v := range []uint64{0, 1, 2, 9, 10, 255, 1 << 40} {
		if s, ok := SuiteFromZioCrypt(v); ok || s != SuiteInherit {
			t.Errorf("SuiteFromZioCrypt(%d) = %v, %v; want inherit, false", v, s, ok)
		}
	}
	for _, s := range []Suite{SuiteInherit, suiteFunction, 200} {
		if s.ZioCrypt() != 0 {
			t.Errorf("%s.ZioCrypt() = %d, want 0", s, s.ZioCrypt())
		}
	}
}

func TestSuiteStringUnknown(t *testing.T) {
	if got := SuiteInherit.String(); got != "inherit" {
		t.Errorf("inherit = %q", got)
	}
	if got := Suite(42).String(); got != "suite(42)" {
		t.Errorf("Suite(42) = %q, want suite(42)", got)
	}
}

// Unwrap and DecryptBlock must refuse a suite that names no algorithm and
// never fall back to GCM for it.
func TestUnknownSuiteIsRefused(t *testing.T) {
	wk := makePattern(WrappingKeyLen, 1)
	iv := makePattern(IVSize, 2)
	mac := makePattern(MACSize, 3)
	blob := makePattern(WrappedKeySize, 4)

	// A blob sealed as AES-256-GCM, so a silent GCM fallback would succeed.
	sealed := aeadFor(t, AES256GCM, wk).Seal(nil, iv, makePattern(WrappedKeySize, 9), nil)
	ct, tag := sealed[:WrappedKeySize], sealed[WrappedKeySize:]

	for _, s := range []Suite{SuiteInherit, suiteFunction, 99} {
		if _, _, err := Unwrap(s, wk, iv, tag, ct, nil); err == nil {
			t.Errorf("Unwrap accepted suite %s", s)
		}
		if _, _, err := Unwrap(s, wk, iv, mac, blob, nil); err == nil {
			t.Errorf("Unwrap accepted suite %s on garbage", s)
		}
		if _, err := DecryptBlock(s, nil, iv, mac, nil, nil); err == nil {
			t.Errorf("DecryptBlock accepted suite %s", s)
		}
	}
	// and the genuine suite does accept that blob.
	if _, _, err := Unwrap(AES256GCM, wk, iv, tag, ct, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestDeriveWrappingKeyRejectsBadIters(t *testing.T) {
	for _, n := range []int{0, -1} {
		if _, err := DeriveWrappingKey([]byte("p"), make([]byte, 8), n); err == nil {
			t.Errorf("iters=%d accepted", n)
		}
	}
}

func TestDeriveBlockKeyRejects(t *testing.T) {
	if _, err := DeriveBlockKey(AES256GCM, make([]byte, 31), make([]byte, 8)); err == nil {
		t.Error("31-byte MEK accepted")
	}
	if _, err := DeriveBlockKey(SuiteInherit, make([]byte, 32), make([]byte, 8)); err == nil {
		t.Error("inherit suite accepted")
	}
}

// Constructor failures are reported with the suite named, not swallowed or
// turned into a panic.
func TestAEADConstructorFailuresAreReported(t *testing.T) {
	boom := errors.New("boom")
	key16, iv, mac := makePattern(16, 1), makePattern(IVSize, 2), makePattern(MACSize, 3)

	oldBlock, oldCCM, oldGCM := newBlock, newCCM, newGCM
	defer func() { newBlock, newCCM, newGCM = oldBlock, oldCCM, oldGCM }()

	newBlock = func([]byte) (cipher.Block, error) { return nil, boom }
	if _, err := DecryptBlock(AES128GCM, key16, iv, mac, nil, nil); !errors.Is(err, boom) {
		t.Errorf("block constructor error lost: %v", err)
	}
	newBlock = oldBlock

	newCCM = func(cipher.Block, int, int) (cipher.AEAD, error) { return nil, boom }
	if _, err := DecryptBlock(AES128CCM, key16, iv, mac, nil, nil); !errors.Is(err, boom) {
		t.Errorf("CCM constructor error lost: %v", err)
	}
	// GCM must not have gone through the CCM constructor.
	if _, err := DecryptBlock(AES128GCM, key16, iv, mac, nil, nil); errors.Is(err, boom) {
		t.Errorf("GCM suite used the CCM constructor")
	}
	newCCM = oldCCM

	newGCM = func(cipher.Block, int) (cipher.AEAD, error) { return nil, boom }
	if _, err := DecryptBlock(AES128GCM, key16, iv, mac, nil, nil); !errors.Is(err, boom) {
		t.Errorf("GCM constructor error lost: %v", err)
	}
	if _, err := DecryptBlock(AES128CCM, key16, iv, mac, nil, nil); errors.Is(err, boom) {
		t.Errorf("CCM suite used the GCM constructor")
	}
}
