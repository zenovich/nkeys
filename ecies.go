// Copyright 2019 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nkeys

import (
	"crypto/rand"
	"crypto/sha512"

	"golang.org/x/crypto/curve25519"
)

func eciesEncrypt(plainText, publicKey []byte) ([]byte, error) {
	var r, R, S, K_B [32]byte

	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	r[0] &= 248
	r[31] &= 127
	r[31] |= 64

	copy(K_B[:], publicKey)

	curve25519.ScalarBaseMult(&R, &r)
	curve25519.ScalarMult(&S, &r, &K_B)
	k_E := sha512.Sum512(S[:])

	cipherText := make([]byte, 32+len(plainText))
	copy(cipherText[:32], R[:])
	for i := 0; i < len(plainText); i++ {
		cipherText[32+i] = plainText[i] ^ k_E[i]
	}
	return cipherText, nil
}

func eciesDecrypt(cipherText, privateKey []byte) ([]byte, error) {
	var R, S, k_B [32]byte
	copy(R[:], cipherText[:32])
	copy(k_B[:], privateKey)

	curve25519.ScalarMult(&S, &k_B, &R)

	k_E := sha512.Sum512(S[:])

	plainText := make([]byte, len(cipherText)-32)
	for i := 0; i < len(plainText); i++ {
		plainText[i] = cipherText[32+i] ^ k_E[i]
	}
	return plainText, nil
}
