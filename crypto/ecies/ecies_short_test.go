// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package ecies

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// CVE-2026-22862: a validly tagged ciphertext whose body is shorter than the
// IV must return an error instead of panicking in symDecrypt.
func TestDecryptShortBody(t *testing.T) {
	prv, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}
	R, err := GenerateKey(rand.Reader, DefaultCurve, nil)
	if err != nil {
		t.Fatal(err)
	}
	params := ParamsFromCurve(DefaultCurve)
	z, err := R.GenerateShared(&prv.PublicKey, params.KeyLen, params.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	hash := params.Hash()
	K, err := concatKDF(hash, z, nil, params.KeyLen+params.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	hash.Write(K[params.KeyLen:])
	Km := hash.Sum(nil)
	body := []byte{0x01}
	c := elliptic.Marshal(DefaultCurve, R.PublicKey.X, R.PublicKey.Y)
	c = append(c, body...)
	c = append(c, messageTag(params.Hash, Km, body, nil)...)

	if _, err := prv.Decrypt(rand.Reader, c, nil, nil); err != ErrInvalidMessage {
		t.Fatalf("got %v, want ErrInvalidMessage", err)
	}
}
