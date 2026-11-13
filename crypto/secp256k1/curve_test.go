// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package secp256k1

import (
	"math/big"
	"testing"
)

// CVE-2026-26314: coordinates >= P must be rejected, otherwise the C library
// panics later when re-encoding the key.
func TestIsOnCurveNonCanonical(t *testing.T) {
	curve := S256()
	x, y := curve.Gx, curve.Gy
	if !curve.IsOnCurve(x, y) {
		t.Fatal("generator not on curve")
	}
	xp := new(big.Int).Add(x, curve.P)
	yp := new(big.Int).Add(y, curve.P)
	if curve.IsOnCurve(xp, y) || curve.IsOnCurve(x, yp) {
		t.Fatal("non-canonical coordinate accepted")
	}
}
