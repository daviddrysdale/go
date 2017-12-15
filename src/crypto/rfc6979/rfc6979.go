// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rfc6979 allows deterministic generation of prime field
// elements according to the mechanism defined in RFC6979.
package rfc6979

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"fmt"
	"math/big"
)

type Generator struct {
	q      *big.Int
	hasher crypto.Hash
	v, k   []byte
	first  bool
}

// NewGenerator builds an object that performs the processing from section 3.2
// of RFC6979, producing new candidate values in the field Z_q on each call to
// Generate().  The private key privKey should be provided as a slice of bytes
// as per RFC6979 s2.3.3, and h1 should be a hash of the input message.
func NewGenerator(q, x *big.Int, h1 []byte, opts crypto.SignerOpts) (*Generator, error) {
	if opts == nil {
		return nil, fmt.Errorf("no options provided")
	}
	h := opts.HashFunc()
	if h == 0 {
		return nil, fmt.Errorf("invalid hash function")
	}
	// Convention throughout: 'size' for bytes, 'len' for bits.
	hsize := h.Size()
	g := Generator{
		q:      q,
		hasher: opts.HashFunc(),
		first:  true,
	}

	// Step a. is assumed already done before the input of h1.
	qlen := g.q.BitLen()
	xo := int2octets(x, (qlen+7)/8)

	// Step b.
	g.v = bytes.Repeat([]byte{0x01}, hsize)

	// Step c.
	g.k = make([]byte, hsize)

	// Step d.
	mac := hmac.New(g.hasher.New, g.k)
	mac.Write(g.v)
	mac.Write([]byte{0x00})
	mac.Write(xo)
	h1o := bits2octets(g.q, h1)
	mac.Write(h1o)
	g.k = mac.Sum(nil)

	// Step e.
	mac = hmac.New(g.hasher.New, g.k)
	mac.Write(g.v)
	g.v = mac.Sum(nil)

	// Step f.
	mac = hmac.New(g.hasher.New, g.k)
	mac.Write(g.v)
	mac.Write([]byte{0x01})
	mac.Write(xo)
	mac.Write(h1o)
	g.k = mac.Sum(nil)

	// Step g.
	mac = hmac.New(g.hasher.New, g.k)
	mac.Write(g.v)
	g.v = mac.Sum(nil)

	// State saved ready for the iterative step h.
	return &g, nil
}

// Generate produces a candidate k value.
func (g *Generator) Generate() (*big.Int, error) {
	// Step h.
	qlen := g.q.BitLen()
	for {
		k := g.generateOne(qlen)
		if k.Sign() == 1 && k.Cmp(g.q) == -1 {
			return k, nil
		}
	}

	return nil, fmt.Errorf("failed to produce valid candidate")
}

// generateOne returns a single candidate value for k, which may be
// invalid either because it is not in the range [1,q], or because
// the outer signature generation process produces zero values.
func (g *Generator) generateOne(qlen int) *big.Int {
	if !g.first {
		// Step h.3. after failed candidate generation.
		mac := hmac.New(g.hasher.New, g.k)
		mac.Write(g.v)
		mac.Write([]byte{0x00})
		g.k = mac.Sum(nil)

		mac = hmac.New(g.hasher.New, g.k)
		mac.Write(g.v)
		g.v = mac.Sum(nil)
	}
	g.first = false

	// Step h.1.
	t := make([]byte, 0, (qlen+7)/8)

	// Step h.2.
	for (8 * len(t)) < qlen {
		mac := hmac.New(g.hasher.New, g.k)
		mac.Write(g.v)
		g.v = mac.Sum(nil)
		t = append(t, g.v...)
	}

	// Step h.3.
	k := bits2int(qlen, t)
	return k
}

// Convert a sequence of bits to a non-negative integer less than 2^qlen, as
// per section 2.3.2.
func bits2int(qlen int, in []byte) *big.Int {
	blen := 8 * len(in)

	var data []byte
	if qlen < blen {
		//  Keep the qlen leftmost bits, and discard subsequent bits.
		rlen := 8 * ((qlen + 7) / 8) // round up to whole number of bytes
		data = make([]byte, (rlen / 8))

		lsize := uint(rlen - qlen) // in bits
		rsize := uint(8 - lsize)   // in bits
		prev := byte(0)
		for i := 0; i < len(data); i++ {
			data[i] = ((prev << rsize) | (in[i] >> lsize))
			prev = in[i]
		}
	} else {
		// Input is smaller than qlen; nominally pad with zeros to the left,
		// but actually just use the input.
		data = in
	}
	var result big.Int
	result.SetBytes(data)
	return &result
}

// Convert a big integer to a byte slice of the given size, as per section 2.3.3
func int2octets(z *big.Int, size int) []byte {
	result := z.Bytes()
	if len(result) < size {
		longerResult := make([]byte, size)
		copy(longerResult[size-len(result):], result)
		return longerResult
	}
	if len(result) > size {
		panic(fmt.Sprintf("Asked to convert a too-long integer %s (vs. size %d)", z.String(), size))
	}
	return result
}

// Convert a sequence of bits to a sequence of bytes, as per section 2.3.4.
func bits2octets(q *big.Int, in []byte) []byte {
	qlen := q.BitLen()
	size := (qlen + 7) / 8
	z1 := bits2int(qlen, in)
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() != 1 {
		return int2octets(z1, size)
	}
	return int2octets(z2, size)
}
