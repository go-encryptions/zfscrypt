// Command zfsjudge is the independent judge for package zfscrypt: it asks
// real OpenZFS to do the encrypting and records what OpenZFS wrote.
//
// It must run as root on a Linux host with the OpenZFS user tools and kernel
// module (zpool, zfs, zdb). For every encryption suite OpenZFS offers it
//
//   - creates a file-backed pool and one passphrase-encrypted dataset per
//     suite (the passphrase comes from a file, never argv);
//   - writes a known two-block file into each, exports the pool;
//   - reads back, with zdb, the DSL crypto key (wrapped master and HMAC
//     keys, IV, MAC, GUID, version, PBKDF2 salt and iterations) and, with
//     zdb -R, each data block's blkptr (salt, IV, MAC), and copies the raw
//     ciphertext out of the pool image;
//   - writes all of it as JSON.
//
// zfscrypt's tests then derive the key, unwrap the master key and decrypt
// the blocks, and demand the plaintext written here. Nothing in this program
// is shared with zfscrypt: a mistake there cannot hide a mistake here.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Passphrase is the fixed test passphrase. It protects nothing.
const Passphrase = "zfscrypt test passphrase"

const (
	blockSize   = 4096
	blocks      = 2
	labelOffset = 4 << 20 // front vdev labels + boot area: vdev offset 0 is image offset 4 MiB
	iters       = 100000  // OpenZFS's minimum pbkdf2iters
)

// Suites are the OpenZFS "encryption" property values, with the on-disk
// zio_crypt_type_t each one must produce (include/sys/fs/zfs.h).
var suites = []struct {
	Name  string
	Crypt uint64
}{
	{"aes-128-ccm", 3}, {"aes-192-ccm", 4}, {"aes-256-ccm", 5},
	{"aes-128-gcm", 6}, {"aes-192-gcm", 7}, {"aes-256-gcm", 8},
}

// Block is one encrypted data block as OpenZFS stored it.
type Block struct {
	Index      int    `json:"index"`
	Salt       []byte `json:"salt"` // 8 bytes, the HKDF info
	IV         []byte `json:"iv"`   // 12 bytes
	MAC        []byte `json:"mac"`  // 16 bytes
	Ciphertext []byte `json:"ciphertext"`
	Plaintext  []byte `json:"plaintext"`
}

// Fixture is everything zfscrypt needs for one suite.
type Fixture struct {
	Suite       string  `json:"suite"`
	Crypt       uint64  `json:"crypt"` // on-disk DSL_CRYPTO_SUITE
	Version     uint64  `json:"version"`
	GUID        uint64  `json:"guid"`
	Passphrase  string  `json:"passphrase"`
	PBKDF2Salt  []byte  `json:"pbkdf2salt"`
	PBKDF2Iters int     `json:"pbkdf2iters"`
	IV          []byte  `json:"iv"`
	MAC         []byte  `json:"mac"`
	MasterKey   []byte  `json:"wrapped_master_key"` // 32 bytes, wrapped
	HMACKey     []byte  `json:"wrapped_hmac_key"`   // 64 bytes, wrapped
	Blocks      []Block `json:"blocks"`
}

// File is the JSON document.
type File struct {
	ZFS      string    `json:"zfs_version"`
	Kernel   string    `json:"kernel"`
	Fixtures []Fixture `json:"fixtures"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: zfsjudge <workdir> <out.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "zfsjudge:", err)
		os.Exit(1)
	}
}

func run(work, out string) error {
	if err := os.RemoveAll(work); err != nil {
		return err
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	pass := filepath.Join(work, "pass")
	if err := os.WriteFile(pass, []byte(Passphrase), 0o600); err != nil {
		return err
	}
	img := filepath.Join(work, "pool.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		return err
	}
	if err := os.Truncate(img, 256<<20); err != nil {
		return err
	}
	const pool = "zfscrypt"
	if _, err := sh("zpool", "create", "-f", "-o", "ashift=12", "-m", "/"+pool, pool, img); err != nil {
		return err
	}
	pooled := true
	defer func() {
		if pooled {
			sh("zpool", "destroy", "-f", pool)
		}
	}()

	inos := map[string]uint64{}
	for _, s := range suites {
		ds := pool + "/" + s.Name
		if _, err := sh("zfs", "create",
			"-o", "encryption="+s.Name, "-o", "keyformat=passphrase",
			"-o", "keylocation=file://"+pass,
			"-o", "pbkdf2iters="+strconv.Itoa(iters),
			"-o", "compression=off", "-o", "recordsize=4096", ds); err != nil {
			return err
		}
		file := "/" + ds + "/data.bin"
		var data []byte
		for i := 0; i < blocks; i++ {
			data = append(data, Plain(s.Name, i)...)
		}
		if err := os.WriteFile(file, data, 0o600); err != nil {
			return err
		}
		st, err := os.Stat(file)
		if err != nil {
			return err
		}
		inos[s.Name] = st.Sys().(*syscall.Stat_t).Ino
	}
	if _, err := sh("sync"); err != nil {
		return err
	}
	if _, err := sh("zpool", "export", pool); err != nil {
		return err
	}
	pooled = false

	zv, _ := sh("zfs", "version")
	kern, _ := sh("uname", "-r")
	f := File{ZFS: strings.Join(strings.Fields(zv), " "), Kernel: strings.TrimSpace(kern)}

	poolDump, err := sh("zdb", "-e", "-p", work, "-dddd", pool)
	if err != nil {
		return err
	}
	keys := parseKeys(poolDump)

	image, err := os.Open(img)
	if err != nil {
		return err
	}
	defer image.Close()

	for _, s := range suites {
		// Each dataset has its own key and every dataset has a distinct
		// suite, so the suite names the key.
		k, ok := keys[s.Crypt]
		if !ok {
			return fmt.Errorf("%s: no DSL crypto key with DSL_CRYPTO_SUITE %d in zdb output", s.Name, s.Crypt)
		}
		fx := Fixture{
			Suite: s.Name, Crypt: k.crypt, Version: k.version, GUID: k.guid,
			Passphrase: Passphrase, PBKDF2Iters: int(k.iters),
			IV: k.iv, MAC: k.mac, MasterKey: k.master, HMACKey: k.hmac,
		}
		fx.PBKDF2Salt = make([]byte, 8)
		binary.LittleEndian.PutUint64(fx.PBKDF2Salt, k.salt)

		dsDump, err := sh("zdb", "-e", "-p", work, "-dddddd", pool+"/"+s.Name)
		if err != nil {
			return err
		}
		l1, err := findL1(dsDump, inos[s.Name])
		if err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		for i := 0; i < blocks; i++ {
			spec := fmt.Sprintf("%d:%x:%x/%x:b%x", l1.vdev, l1.off, l1.lsize, l1.psize, i*128)
			txt, err := sh("zdb", "-e", "-p", work, "-R", pool, spec)
			if err != nil {
				return fmt.Errorf("%s: zdb -R %s: %w", s.Name, spec, err)
			}
			b, err := parseBlkptr(txt)
			if err != nil {
				return fmt.Errorf("%s: block %d: %w", s.Name, i, err)
			}
			b.Index = i
			b.Ciphertext = make([]byte, blockSize)
			if _, err := image.ReadAt(b.Ciphertext, labelOffset+b.off); err != nil {
				return err
			}
			b.Plaintext = Plain(s.Name, i)
			fx.Blocks = append(fx.Blocks, b.Block)
		}
		f.Fixtures = append(f.Fixtures, fx)
	}
	j, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(j, '\n'), 0o644)
}

// Plain is the known plaintext of block i of a suite's file: readable text
// repeated to the block size, so a wrong decryption cannot look right.
func Plain(suite string, i int) []byte {
	unit := []byte(fmt.Sprintf("zfscrypt openzfs judge | %s | block %d | ", suite, i))
	return bytes.Repeat(unit, blockSize/len(unit)+1)[:blockSize]
}

func sh(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if err := cmd.Run(); err != nil {
		return o.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, e.String())
	}
	return o.String(), nil
}

type key struct {
	crypt, version, guid, iters, salt uint64
	iv, mac, master, hmac             []byte
}

// parseKeys reads every DSL crypto key ZAP out of a `zdb -dddd <pool>` dump
// (the lines DSL_CRYPTO_SUITE = ..., pbkdf2salt = ..., one ZAP per key),
// indexed by DSL_CRYPTO_SUITE.
func parseKeys(dump string) map[uint64]key {
	out := map[uint64]key{}
	var cur *key
	flush := func() {
		// Only a ZAP that carries DSL_CRYPTO_SUITE is a crypto key.
		if cur != nil && cur.crypt != 0 {
			out[cur.crypt] = *cur
		}
		cur = nil
	}
	sc := bufio.NewScanner(strings.NewReader(dump))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// Each object starts with a header line; its ZAP entries follow, in
		// hash order, so DSL_CRYPTO_SUITE is not necessarily the first.
		if strings.HasPrefix(line, "Object ") {
			flush()
			cur = &key{}
			continue
		}
		name, val, ok := strings.Cut(line, " = ")
		if !ok || cur == nil {
			continue
		}
		val = strings.TrimSpace(val)
		switch name {
		case "DSL_CRYPTO_SUITE":
			cur.crypt, _ = strconv.ParseUint(val, 10, 64)
		case "DSL_CRYPTO_VERSION":
			cur.version, _ = strconv.ParseUint(val, 10, 64)
		case "DSL_CRYPTO_GUID":
			// zdb prints the 64-bit GUID as signed when the top bit is set.
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				u, uerr := strconv.ParseUint(val, 10, 64)
				if uerr != nil {
					panic("DSL_CRYPTO_GUID " + val + ": " + uerr.Error())
				}
				n = int64(u)
			}
			cur.guid = uint64(n)
		case "pbkdf2iters":
			cur.iters, _ = strconv.ParseUint(val, 10, 64)
		case "pbkdf2salt":
			// zdb prints the 64-bit value as signed.
			n, _ := strconv.ParseInt(val, 10, 64)
			cur.salt = uint64(n)
		case "DSL_CRYPTO_IV":
			cur.iv, _ = hex.DecodeString(val)
		case "DSL_CRYPTO_MAC":
			cur.mac, _ = hex.DecodeString(val)
		case "DSL_CRYPTO_MASTER_KEY_1":
			cur.master, _ = hex.DecodeString(val)
		case "DSL_CRYPTO_HMAC_KEY_1":
			cur.hmac, _ = hex.DecodeString(val)
		}
	}
	flush()
	return out
}

type l1 struct {
	vdev, off, lsize, psize uint64
}

var l1Line = regexp.MustCompile(`^\s+\d+\s+L1\s+(\d+):([0-9a-f]+):[0-9a-f]+\s.*\s([0-9a-f]+)L/([0-9a-f]+)P`)

// findL1 finds the first DVA of the L1 indirect block of object ino in a
// `zdb -dddddd <dataset>` dump.
func findL1(dump string, ino uint64) (l1, error) {
	in := false
	sc := bufio.NewScanner(strings.NewReader(dump))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := objRe.FindStringSubmatch(line); m != nil {
			n, _ := strconv.ParseUint(m[1], 10, 64)
			in = n == ino && strings.Contains(m[2], "plain file")
		}
		if !in {
			continue
		}
		if m := l1Line.FindStringSubmatch(line); m != nil {
			var r l1
			r.vdev, _ = strconv.ParseUint(m[1], 10, 64)
			r.off, _ = strconv.ParseUint(m[2], 16, 64)
			r.lsize, _ = strconv.ParseUint(m[3], 16, 64)
			r.psize, _ = strconv.ParseUint(m[4], 16, 64)
			return r, nil
		}
	}
	return l1{}, fmt.Errorf("object %d: no L1 indirect block in zdb output", ino)
}

// objRe matches an object header: "<id> <lvl> <iblk> <dblk> <dsize> <dnsize> <lsize> <%full> <type>".
var objRe = regexp.MustCompile(`^\s+(\d+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\d+\s+\S+\s+[\d.]+\s+(.*)$`)

type parsedBlock struct {
	Block
	off int64
}

var (
	dvaRe  = regexp.MustCompile(`DVA\[0\]=<(\d+):([0-9a-f]+):([0-9a-f]+)>`)
	saltRe = regexp.MustCompile(`salt=([0-9a-f]+) iv=([0-9a-f]+):([0-9a-f]+)`)
	ckRe   = regexp.MustCompile(`cksum=([0-9a-f]+):([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)`)
)

// parseBlkptr turns zdb's blkptr line into a block. OpenZFS stores the
// salt, the IV and the MAC as native (little-endian) 64-bit words:
//
//	salt = word 0 of DVA[2];  iv = word 1 of DVA[2] || low 32 bits of blk_fill
//	mac  = checksum words 2 and 3
//
// and zdb prints those words as numbers, so each is re-serialised
// little-endian here.
func parseBlkptr(txt string) (parsedBlock, error) {
	var b parsedBlock
	d := dvaRe.FindStringSubmatch(txt)
	s := saltRe.FindStringSubmatch(txt)
	c := ckRe.FindStringSubmatch(txt)
	if d == nil || s == nil || c == nil {
		return b, errors.New("zdb -R output has no encrypted blkptr: " + strings.TrimSpace(txt))
	}
	off, _ := strconv.ParseUint(d[2], 16, 63)
	b.off = int64(off)
	salt, _ := strconv.ParseUint(s[1], 16, 64)
	iv1, _ := strconv.ParseUint(s[2], 16, 64)
	iv2, _ := strconv.ParseUint(s[3], 16, 32)
	c2, _ := strconv.ParseUint(c[3], 16, 64)
	c3, _ := strconv.ParseUint(c[4], 16, 64)
	b.Salt = binary.LittleEndian.AppendUint64(nil, salt)
	b.IV = binary.LittleEndian.AppendUint64(nil, iv1)
	b.IV = binary.LittleEndian.AppendUint32(b.IV, uint32(iv2))
	b.MAC = binary.LittleEndian.AppendUint64(nil, c2)
	b.MAC = binary.LittleEndian.AppendUint64(b.MAC, c3)
	return b, nil
}
