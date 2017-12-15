// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
)

func testKeyGeneration(t *testing.T, c elliptic.Curve, tag string) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("%s: public key invalid: %s", tag, err)
	}
}

func TestKeyGeneration(t *testing.T) {
	testKeyGeneration(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testKeyGeneration(t, elliptic.P256(), "p256")
	testKeyGeneration(t, elliptic.P384(), "p384")
	testKeyGeneration(t, elliptic.P521(), "p521")
}

func BenchmarkSignP256(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()
	hashed := []byte("testing")
	priv, _ := GenerateKey(p256, rand.Reader)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = Sign(rand.Reader, priv, hashed)
		}
	})
}

func BenchmarkSignP384(b *testing.B) {
	b.ResetTimer()
	p384 := elliptic.P384()
	hashed := []byte("testing")
	priv, _ := GenerateKey(p384, rand.Reader)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = Sign(rand.Reader, priv, hashed)
		}
	})
}

func BenchmarkVerifyP256(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()
	hashed := []byte("testing")
	priv, _ := GenerateKey(p256, rand.Reader)
	r, s, _ := Sign(rand.Reader, priv, hashed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Verify(&priv.PublicKey, hashed, r, s)
		}
	})
}

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			GenerateKey(p256, rand.Reader)
		}
	})
}

func testSignAndVerify(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify failed", tag)
	}

	hashed[0] ^= 0xff
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify always works!", tag)
	}
}

func testDeterministicSignAndVerify(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateDeterministicKey(c, rand.Reader)

	hashed := []byte("testing")
	r, s, err := DeterministicSign(priv, hashed, crypto.SHA256)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}
	r2, s2, err := DeterministicSign(priv, hashed, crypto.SHA256)
	if err != nil {
		t.Errorf("%s: error re-signing: %s", tag, err)
		return
	}
	if r.Cmp(r2) != 0 || s.Cmp(s2) != 0 {
		t.Errorf("%s: different results on repeated sign: (%v, %v) vs. (%v, %v)", tag, r, s, r2, s2)
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify failed", tag)
	}

	hashed[0] ^= 0xff
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify always works!", tag)
	}
}

func TestSignAndVerify(t *testing.T) {
	testSignAndVerify(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testSignAndVerify(t, elliptic.P256(), "p256")
	testSignAndVerify(t, elliptic.P384(), "p384")
	testSignAndVerify(t, elliptic.P521(), "p521")
}

func TestDeterministicSignAndVerify(t *testing.T) {
	testDeterministicSignAndVerify(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testSignAndVerify(t, elliptic.P256(), "p256")
	testSignAndVerify(t, elliptic.P384(), "p384")
	testSignAndVerify(t, elliptic.P521(), "p521")
}

func testNonceSafety(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := Sign(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	hashed = []byte("testing...")
	r1, s1, err := Sign(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if s0.Cmp(s1) == 0 {
		// This should never happen.
		t.Errorf("%s: the signatures on two different messages were the same", tag)
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("%s: the nonce used for two different messages was the same", tag)
	}
}

func TestNonceSafety(t *testing.T) {
	testNonceSafety(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testNonceSafety(t, elliptic.P256(), "p256")
	testNonceSafety(t, elliptic.P384(), "p384")
	testNonceSafety(t, elliptic.P521(), "p521")
}

func testINDCCA(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	r1, s1, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if s0.Cmp(s1) == 0 {
		t.Errorf("%s: two signatures of the same message produced the same result", tag)
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("%s: two signatures of the same message produced the same nonce", tag)
	}
}

func TestINDCCA(t *testing.T) {
	testINDCCA(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testINDCCA(t, elliptic.P256(), "p256")
	testINDCCA(t, elliptic.P384(), "p384")
	testINDCCA(t, elliptic.P521(), "p521")
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex")
	}
	return r
}

func TestVectors(t *testing.T) {
	// This test runs the full set of NIST test vectors from
	// http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip
	//
	// The SigVer.rsp file has been edited to remove test vectors for
	// unsupported algorithms and has been compressed.

	if testing.Short() {
		return
	}

	f, err := os.Open("testdata/SigVer.rsp.bz2")
	if err != nil {
		t.Fatal(err)
	}

	buf := bufio.NewReader(bzip2.NewReader(f))

	lineNo := 1
	var h hash.Hash
	var msg []byte
	var hashed []byte
	var r, s *big.Int
	pub := new(PublicKey)

	for {
		line, err := buf.ReadString('\n')
		if len(line) == 0 {
			if err == io.EOF {
				break
			}
			t.Fatalf("error reading from input: %s", err)
		}
		lineNo++
		// Need to remove \r\n from the end of the line.
		if !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("bad line ending (expected \\r\\n) on line %d", lineNo)
		}
		line = line[:len(line)-2]

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if line[0] == '[' {
			line = line[1 : len(line)-1]
			parts := strings.SplitN(line, ",", 2)

			switch parts[0] {
			case "P-224":
				pub.Curve = elliptic.P224()
			case "P-256":
				pub.Curve = elliptic.P256()
			case "P-384":
				pub.Curve = elliptic.P384()
			case "P-521":
				pub.Curve = elliptic.P521()
			default:
				pub.Curve = nil
			}

			switch parts[1] {
			case "SHA-1":
				h = sha1.New()
			case "SHA-224":
				h = sha256.New224()
			case "SHA-256":
				h = sha256.New()
			case "SHA-384":
				h = sha512.New384()
			case "SHA-512":
				h = sha512.New()
			default:
				h = nil
			}

			continue
		}

		if h == nil || pub.Curve == nil {
			continue
		}

		switch {
		case strings.HasPrefix(line, "Msg = "):
			if msg, err = hex.DecodeString(line[6:]); err != nil {
				t.Fatalf("failed to decode message on line %d: %s", lineNo, err)
			}
		case strings.HasPrefix(line, "Qx = "):
			pub.X = fromHex(line[5:])
		case strings.HasPrefix(line, "Qy = "):
			pub.Y = fromHex(line[5:])
		case strings.HasPrefix(line, "R = "):
			r = fromHex(line[4:])
		case strings.HasPrefix(line, "S = "):
			s = fromHex(line[4:])
		case strings.HasPrefix(line, "Result = "):
			expected := line[9] == 'P'
			h.Reset()
			h.Write(msg)
			hashed := h.Sum(hashed[:0])
			if Verify(pub, hashed, r, s) != expected {
				t.Fatalf("incorrect result on line %d", lineNo)
			}
		default:
			t.Fatalf("unknown variable on line %d: %s", lineNo, line)
		}
	}
}

func testNegativeInputs(t *testing.T, curve elliptic.Curve, tag string) {
	key, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("failed to generate key for %q", tag)
	}

	var hash [32]byte
	r := new(big.Int).SetInt64(1)
	r.Lsh(r, 550 /* larger than any supported curve */)
	r.Neg(r)

	if Verify(&key.PublicKey, hash[:], r, r) {
		t.Errorf("bogus signature accepted for %q", tag)
	}
}

func TestNegativeInputs(t *testing.T) {
	testNegativeInputs(t, elliptic.P224(), "p224")
	testNegativeInputs(t, elliptic.P256(), "p256")
	testNegativeInputs(t, elliptic.P384(), "p384")
	testNegativeInputs(t, elliptic.P521(), "p521")
}

func TestZeroHashSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		privKey, err := GenerateKey(curve, rand.Reader)
		if err != nil {
			panic(err)
		}

		// Sign a hash consisting of all zeros.
		r, s, err := Sign(rand.Reader, privKey, zeroHash)
		if err != nil {
			panic(err)
		}

		// Confirm that it can be verified.
		if !Verify(&privKey.PublicKey, zeroHash, r, s) {
			t.Errorf("zero hash signature verify failed for %T", curve)
		}
	}
}

func h2i(s string) *big.Int {
	result, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(fmt.Sprintf("fixture data %q corrupt", s))
	}
	return result
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA224:
		return "SHA224"
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("hash-%d", h)
	}
}

func TestDeterministicSignRFC6979Vectors(t *testing.T) {
	type keyInfo struct {
		priv   DeterministicPrivateKey
		keylen int
		q      *big.Int
	}
	privateKeys := map[string]keyInfo{
		// TODO(drysdale): reinstate if/when Go adds support for P-192.
		/*
			"P-192": keyInfo{
				priv: DeterministicPrivateKey{
					PublicKey: PublicKey{
						Curve: elliptic.P192(),
						X:     h2i("AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56"),
						Y:     h2i("3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43"),
					},
					D: h2i("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4"),
				},
				keylen: 192,
				q:      h2i("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"),
			},
		*/
		"P-224": keyInfo{
			priv: DeterministicPrivateKey{
				PublicKey: PublicKey{
					Curve: elliptic.P224(),
					X:     h2i("00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C"),
					Y:     h2i("EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A"),
				},
				D: h2i("F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1"),
			},
			keylen: 224,
			q:      h2i("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"),
		},
		"P-256": keyInfo{
			priv: DeterministicPrivateKey{
				PublicKey: PublicKey{
					Curve: elliptic.P256(),
					X:     h2i("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"),
					Y:     h2i("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"),
				},
				D: h2i("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"),
			},
			keylen: 256,
			q:      h2i("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
		},
		"P-384": keyInfo{
			priv: DeterministicPrivateKey{
				PublicKey: PublicKey{
					Curve: elliptic.P384(),
					X: h2i("EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64" +
						"DEF8F0EA9055866064A254515480BC13"),
					Y: h2i("8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1" +
						"288B231C3AE0D4FE7344FD2533264720"),
				},
				D: h2i("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8" +
					"96D5724E4C70A825F872C9EA60D2EDF5"),
			},
			keylen: 384,
			q: h2i("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF" +
				"581A0DB248B0A77AECEC196ACCC52973"),
		},
		"P-521": keyInfo{
			priv: DeterministicPrivateKey{
				PublicKey: PublicKey{
					Curve: elliptic.P521(),
					X: h2i("1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3" +
						"71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502" +
						"3A4"),
					Y: h2i("0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2" +
						"8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF" +
						"CF5"),
				},
				D: h2i("0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C" +
					"AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83" +
					"538"),
			},
			keylen: 521,
			q: h2i("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
				"FFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386" +
				"409"),
		},
	}

	// Check key values.
	for name, info := range privateKeys {
		n := info.priv.Params().N
		if got, want := n.BitLen(), info.keylen; got != want {
			t.Errorf("privateKeys[%q].D.BitLen()=%d, want %d", name, got, want)
		}
		if got, want := n, info.q; got.Cmp(want) != 0 {
			t.Errorf("privateKeys[%q].Params.N=%s, want %s", name, got.String(), want.String())
		}
	}

	var tests = []struct {
		key  string
		hash crypto.Hash
		msg  string
		k    *big.Int
		r, s *big.Int
	}{
		// Section A.2.3, P-192 (cases will be skipped due to no Golang P-192 support).
		{
			key:  "P-192",
			hash: crypto.SHA1,
			msg:  "sample",
			k:    h2i("37D7CA00D2C7B0E5E412AC03BD44BA837FDD5B28CD3B0021"),
			r:    h2i("98C6BD12B23EAF5E2A2045132086BE3EB8EBD62ABF6698FF"),
			s:    h2i("57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA224,
			msg:  "sample",
			k:    h2i("4381526B3FC1E7128F202E194505592F01D5FF4C5AF015D8"),
			r:    h2i("A1F00DAD97AEEC91C95585F36200C65F3C01812AA60378F5"),
			s:    h2i("E07EC1304C7C6C9DEBBE980B9692668F81D4DE7922A0F97A"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA256,
			msg:  "sample",
			k:    h2i("32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496"),
			r:    h2i("4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55"),
			s:    h2i("CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA384,
			msg:  "sample",
			k:    h2i("4730005C4FCB01834C063A7B6760096DBE284B8252EF4311"),
			r:    h2i("DA63BF0B9ABCF948FBB1E9167F136145F7A20426DCC287D5"),
			s:    h2i("C3AA2C960972BD7A2003A57E1C4C77F0578F8AE95E31EC5E"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA512,
			msg:  "sample",
			k:    h2i("A2AC7AB055E4F20692D49209544C203A7D1F2C0BFBC75DB1"),
			r:    h2i("4D60C5AB1996BD848343B31C00850205E2EA6922DAC2E4B8"),
			s:    h2i("3F6E837448F027A1BF4B34E796E32A811CBB4050908D8F67"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA1,
			msg:  "test",
			k:    h2i("D9CF9C3D3297D3260773A1DA7418DB5537AB8DD93DE7FA25"),
			r:    h2i("0F2141A0EBBC44D2E1AF90A50EBCFCE5E197B3B7D4DE036D"),
			s:    h2i("EB18BC9E1F3D7387500CB99CF5F7C157070A8961E38700B7"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA224,
			msg:  "test",
			k:    h2i("F5DC805F76EF851800700CCE82E7B98D8911B7D510059FBE"),
			r:    h2i("6945A1C1D1B2206B8145548F633BB61CEF04891BAF26ED34"),
			s:    h2i("B7FB7FDFC339C0B9BD61A9F5A8EAF9BE58FC5CBA2CB15293"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA256,
			msg:  "test",
			k:    h2i("5C4CE89CF56D9E7C77C8585339B006B97B5F0680B4306C6C"),
			r:    h2i("3A718BD8B4926C3B52EE6BBE67EF79B18CB6EB62B1AD97AE"),
			s:    h2i("5662E6848A4A19B1F1AE2F72ACD4B8BBE50F1EAC65D9124F"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA384,
			msg:  "test",
			k:    h2i("5AFEFB5D3393261B828DB6C91FBC68C230727B030C975693"),
			r:    h2i("B234B60B4DB75A733E19280A7A6034BD6B1EE88AF5332367"),
			s:    h2i("7994090B2D59BB782BE57E74A44C9A1C700413F8ABEFE77A"),
		},
		{
			key:  "P-192",
			hash: crypto.SHA512,
			msg:  "test",
			k:    h2i("0758753A5254759C7CFBAD2E2D9B0792EEE44136C9480527"),
			r:    h2i("FE4F4AE86A58B6507946715934FE2D8FF9D95B6B098FE739"),
			s:    h2i("74CF5605C98FBA0E1EF34D4B5A1577A7DCF59457CAE52290"),
		},

		// Section A.2.4, P-224.
		{
			key:  "P-224",
			hash: crypto.SHA1,
			msg:  "sample",
			k:    h2i("7EEFADD91110D8DE6C2C470831387C50D3357F7F4D477054B8B426BC"),
			r:    h2i("22226F9D40A96E19C4A301CE5B74B115303C0F3A4FD30FC257FB57AC"),
			s:    h2i("66D1CDD83E3AF75605DD6E2FEFF196D30AA7ED7A2EDF7AF475403D69"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA224,
			msg:  "sample",
			k:    h2i("C1D1F2F10881088301880506805FEB4825FE09ACB6816C36991AA06D"),
			r:    h2i("1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E"),
			s:    h2i("A6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA256,
			msg:  "sample",
			k:    h2i("AD3029E0278F80643DE33917CE6908C70A8FF50A411F06E41DEDFCDC"),
			r:    h2i("61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA"),
			s:    h2i("BC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA384,
			msg:  "sample",
			k:    h2i("52B40F5A9D3D13040F494E83D3906C6079F29981035C7BD51E5CAC40"),
			r:    h2i("0B115E5E36F0F9EC81F1325A5952878D745E19D7BB3EABFABA77E953"),
			s:    h2i("830F34CCDFE826CCFDC81EB4129772E20E122348A2BBD889A1B1AF1D"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA512,
			msg:  "sample",
			k:    h2i("9DB103FFEDEDF9CFDBA05184F925400C1653B8501BAB89CEA0FBEC14"),
			r:    h2i("074BD1D979D5F32BF958DDC61E4FB4872ADCAFEB2256497CDAC30397"),
			s:    h2i("A4CECA196C3D5A1FF31027B33185DC8EE43F288B21AB342E5D8EB084"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA1,
			msg:  "test",
			k:    h2i("2519178F82C3F0E4F87ED5883A4E114E5B7A6E374043D8EFD329C253"),
			r:    h2i("DEAA646EC2AF2EA8AD53ED66B2E2DDAA49A12EFD8356561451F3E21C"),
			s:    h2i("95987796F6CF2062AB8135271DE56AE55366C045F6D9593F53787BD2"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA224,
			msg:  "test",
			k:    h2i("DF8B38D40DCA3E077D0AC520BF56B6D565134D9B5F2EAE0D34900524"),
			r:    h2i("C441CE8E261DED634E4CF84910E4C5D1D22C5CF3B732BB204DBEF019"),
			s:    h2i("902F42847A63BDC5F6046ADA114953120F99442D76510150F372A3F4"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA256,
			msg:  "test",
			k:    h2i("FF86F57924DA248D6E44E8154EB69F0AE2AEBAEE9931D0B5A969F904"),
			r:    h2i("AD04DDE87B84747A243A631EA47A1BA6D1FAA059149AD2440DE6FBA6"),
			s:    h2i("178D49B1AE90E3D8B629BE3DB5683915F4E8C99FDF6E666CF37ADCFD"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA384,
			msg:  "test",
			k:    h2i("7046742B839478C1B5BD31DB2E862AD868E1A45C863585B5F22BDC2D"),
			r:    h2i("389B92682E399B26518A95506B52C03BC9379A9DADF3391A21FB0EA4"),
			s:    h2i("414A718ED3249FF6DBC5B50C27F71F01F070944DA22AB1F78F559AAB"),
		},
		{
			key:  "P-224",
			hash: crypto.SHA512,
			msg:  "test",
			k:    h2i("E39C2AA4EA6BE2306C72126D40ED77BF9739BB4D6EF2BBB1DCB6169D"),
			r:    h2i("049F050477C5ADD858CAC56208394B5A55BAEBBE887FDF765047C17C"),
			s:    h2i("077EB13E7005929CEFA3CD0403C7CDCC077ADF4E44F3C41B2F60ECFF"),
		},

		// A.2.5, P-256.
		{
			key:  "P-256",
			hash: crypto.SHA1,
			msg:  "sample",
			k:    h2i("882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4"),
			r:    h2i("61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32"),
			s:    h2i("6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA224,
			msg:  "sample",
			k:    h2i("103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473"),
			r:    h2i("53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F"),
			s:    h2i("B9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA256,
			msg:  "sample",
			k:    h2i("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"),
			r:    h2i("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
			s:    h2i("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA384,
			msg:  "sample",
			k:    h2i("09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4"),
			r:    h2i("0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719"),
			s:    h2i("4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA512,
			msg:  "sample",
			k:    h2i("5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5"),
			r:    h2i("8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00"),
			s:    h2i("2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA1,
			msg:  "test",
			k:    h2i("8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2E"),
			r:    h2i("0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89"),
			s:    h2i("01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA224,
			msg:  "test",
			k:    h2i("669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7"),
			r:    h2i("C37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692"),
			s:    h2i("C820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA256,
			msg:  "test",
			k:    h2i("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0"),
			r:    h2i("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"),
			s:    h2i("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA384,
			msg:  "test",
			k:    h2i("16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8"),
			r:    h2i("83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6"),
			s:    h2i("8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C"),
		},
		{
			key:  "P-256",
			hash: crypto.SHA512,
			msg:  "test",
			k:    h2i("6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F"),
			r:    h2i("461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04"),
			s:    h2i("39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55"),
		},

		// A.2.6, P-384.
		{
			key:  "P-384",
			hash: crypto.SHA1,
			msg:  "sample",
			k: h2i("4471EF7518BB2C7C20F62EAE1C387AD0C5E8E470995DB4ACF694466E6AB09663" +
				"0F29E5938D25106C3C340045A2DB01A7"),
			r: h2i("EC748D839243D6FBEF4FC5C4859A7DFFD7F3ABDDF72014540C16D73309834FA3" +
				"7B9BA002899F6FDA3A4A9386790D4EB2"),
			s: h2i("A3BCFA947BEEF4732BF247AC17F71676CB31A847B9FF0CBC9C9ED4C1A5B3FACF" +
				"26F49CA031D4857570CCB5CA4424A443"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA224,
			msg:  "sample",
			k: h2i("A4E4D2F0E729EB786B31FC20AD5D849E304450E0AE8E3E341134A5C1AFA03CAB" +
				"8083EE4E3C45B06A5899EA56C51B5879"),
			r: h2i("42356E76B55A6D9B4631C865445DBE54E056D3B3431766D0509244793C3F9366" +
				"450F76EE3DE43F5A125333A6BE060122"),
			s: h2i("9DA0C81787064021E78DF658F2FBB0B042BF304665DB721F077A4298B095E483" +
				"4C082C03D83028EFBF93A3C23940CA8D"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA256,
			msg:  "sample",
			k: h2i("180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E" +
				"375572342863C899F9F2EDF9747A9B60"),
			r: h2i("21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33" +
				"BDE1E888E63355D92FA2B3C36D8FB2CD"),
			s: h2i("F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEB" +
				"EFDC63ECCD1AC42EC0CB8668A4FA0AB0"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA384,
			msg:  "sample",
			k: h2i("94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA" +
				"2907E3E83BA95368623B8C4686915CF9"),
			r: h2i("94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C" +
				"81A648152E44ACF96E36DD1E80FABE46"),
			s: h2i("99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F" +
				"A329C145786E679E7B82C71A38628AC8"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA512,
			msg:  "sample",
			k: h2i("92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331" +
				"A4E966532593A52980D0E3AAA5E10EC3"),
			r: h2i("ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799C" +
				"FE30F35CC900056D7C99CD7882433709"),
			s: h2i("512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112" +
				"DC7CC3EF3446DEFCEB01A45C2667FDD5"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA1,
			msg:  "test",
			k: h2i("66CC2C8F4D303FC962E5FF6A27BD79F84EC812DDAE58CF5243B64A4AD8094D47" +
				"EC3727F3A3C186C15054492E30698497"),
			r: h2i("4BC35D3A50EF4E30576F58CD96CE6BF638025EE624004A1F7789A8B8E43D0678" +
				"ACD9D29876DAF46638645F7F404B11C7"),
			s: h2i("D5A6326C494ED3FF614703878961C0FDE7B2C278F9A65FD8C4B7186201A29916" +
				"95BA1C84541327E966FA7B50F7382282"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA224,
			msg:  "test",
			k: h2i("18FA39DB95AA5F561F30FA3591DC59C0FA3653A80DAFFA0B48D1A4C6DFCBFF6E" +
				"3D33BE4DC5EB8886A8ECD093F2935726"),
			r: h2i("E8C9D0B6EA72A0E7837FEA1D14A1A9557F29FAA45D3E7EE888FC5BF954B5E624" +
				"64A9A817C47FF78B8C11066B24080E72"),
			s: h2i("07041D4A7A0379AC7232FF72E6F77B6DDB8F09B16CCE0EC3286B2BD43FA8C614" +
				"1C53EA5ABEF0D8231077A04540A96B66"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA256,
			msg:  "test",
			k: h2i("0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FA" +
				"A48DD070BA79921A3457ABFF2D630AD7"),
			r: h2i("6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559" +
				"F918EEDAF2293BE5B475CC8F0188636B"),
			s: h2i("2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D" +
				"51AB373F9845C0514EEFB14024787265"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA384,
			msg:  "test",
			k: h2i("015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092AD" +
				"A71F4A459BC0DA98ADB95837DB8312EA"),
			r: h2i("8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB" +
				"0542A7F0812998DA8F1DD3CA3CF023DB"),
			s: h2i("DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E0" +
				"6A739F040649A667BF3B828246BAA5A5"),
		},
		{
			key:  "P-384",
			hash: crypto.SHA512,
			msg:  "test",
			k: h2i("3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE" +
				"0E2CC8A136036DC4B9C00E6888F66B6C"),
			r: h2i("A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D0" +
				"6FB6495CD21B4B6E340FC236584FB277"),
			s: h2i("976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B22463" +
				"4A2092CD3792E0159AD9CEE37659C736"),
		},

		// A.2.7,  P-521.
		{
			key:  "P-521",
			hash: crypto.SHA1,
			msg:  "sample",
			k: h2i("089C071B419E1C2820962321787258469511958E80582E95D8378E0C2CCDB3CB" +
				"42BEDE42F50E3FA3C71F5A76724281D31D9C89F0F91FC1BE4918DB1C03A5838D" +
				"0F9"),
			r: h2i("0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910" +
				"FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D" +
				"75D"),
			s: h2i("0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D" +
				"5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5" +
				"D16"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA224,
			msg:  "sample",
			k: h2i("121415EC2CD7726330A61F7F3FA5DE14BE9436019C4DB8CB4041F3B54CF31BE0" +
				"493EE3F427FB906393D895A19C9523F3A1D54BB8702BD4AA9C99DAB2597B9211" +
				"3F3"),
			r: h2i("1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A3" +
				"0715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2E" +
				"D2E"),
			s: h2i("050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17B" +
				"A41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B" +
				"41F"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA256,
			msg:  "sample",
			k: h2i("0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C3257576" +
				"1793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E" +
				"1A0"),
			r: h2i("1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659" +
				"D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E" +
				"1A7"),
			s: h2i("04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916" +
				"E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7E" +
				"CFC"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA384,
			msg:  "sample",
			k: h2i("1546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FF" +
				"AD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4" +
				"211"),
			r: h2i("1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4" +
				"B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67" +
				"451"),
			s: h2i("1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5" +
				"FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65" +
				"D61"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA512,
			msg:  "sample",
			k: h2i("1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F1019" +
				"8B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBF" +
				"FD3"),
			r: h2i("0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1" +
				"74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37" +
				"7FA"),
			s: h2i("0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2" +
				"82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A" +
				"67A"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA1,
			msg:  "test",
			k: h2i("0BB9F2BF4FE1038CCF4DABD7139A56F6FD8BB1386561BD3C6A4FC818B20DF5DD" +
				"BA80795A947107A1AB9D12DAA615B1ADE4F7A9DC05E8E6311150F47F5C57CE8B" +
				"222"),
			r: h2i("13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0" +
				"693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0" +
				"367"),
			s: h2i("1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90" +
				"F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC91679" +
				"7FF"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA224,
			msg:  "test",
			k: h2i("040D09FCF3C8A5F62CF4FB223CBBB2B9937F6B0577C27020A99602C25A011369" +
				"87E452988781484EDBBCF1C47E554E7FC901BC3085E5206D9F619CFF07E73D6F" +
				"706"),
			r: h2i("1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086" +
				"BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE1" +
				"7FB"),
			s: h2i("177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5" +
				"BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD51" +
				"9A4"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA256,
			msg:  "test",
			k: h2i("01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E84384" +
				"1AF09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909" +
				"258"),
			r: h2i("00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D807104" +
				"2EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656" +
				"AA8"),
			s: h2i("0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9" +
				"FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694" +
				"E86"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA384,
			msg:  "test",
			k: h2i("1F1FC4A349A7DA9A9E116BFDD055DC08E78252FF8E23AC276AC88B1770AE0B5D" +
				"CEB1ED14A4916B769A523CE1E90BA22846AF11DF8B300C38818F713DADD85DE0" +
				"C88"),
			r: h2i("14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C" +
				"89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF60755" +
				"78C"),
			s: h2i("133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0E" +
				"D94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B" +
				"979"),
		},
		{
			key:  "P-521",
			hash: crypto.SHA512,
			msg:  "test",
			k: h2i("16200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1" +
				"B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC" +
				"56D"),
			r: h2i("13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10" +
				"CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47E" +
				"E6D"),
			s: h2i("1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78" +
				"A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4D" +
				"CE3"),
		},
	}

	for _, test := range tests {
		ki, ok := privateKeys[test.key]
		if !ok {
			continue
		}

		hasher := test.hash.New()
		hasher.Write([]byte(test.msg))
		h1 := hasher.Sum(nil)

		got, err := ki.priv.Sign(nil, h1, test.hash)
		if err != nil {
			t.Errorf("key.Sign(%s, %s(%q))=nil, %v; want _, nil", test.key, hashName(test.hash), test.msg, err)
			continue
		}
		want, _ := asn1.Marshal(ecdsaSignature{test.r, test.s})
		if !bytes.Equal(got, want) {
			t.Errorf("key.Sign(%s, %s(%q))=%x; want %x", test.key, hashName(test.hash), test.msg, got, want)
			continue
		}
	}
}
