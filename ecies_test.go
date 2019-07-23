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
	"bytes"
	"testing"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
)

func TestCurveConversion(t *testing.T) {
	bob, err := CreateUser()
	if err != nil {
		t.Fatalf("Error creating new user: %v", err)
	}
	_public, _private, err := bob.(*kp).keys()
	if err != nil {
		t.Fatalf("Error getting keys: %v", err)
	}
	var public [32]byte
	var private [64]byte

	copy(public[:], _public)
	copy(private[:], _private)

	var curve25519Public, curve25519Public2, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, &private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	if !extra25519.PublicKeyToCurve25519(&curve25519Public2, &public) {
		t.Fatalf("Error converting public key: %v", err)
	}

	if !bytes.Equal(curve25519Public[:], curve25519Public2[:]) {
		t.Fatalf("Public keys do not match: %x vs %x", curve25519Public[:], curve25519Public2[:])
	}
}

func TestEncrypt(t *testing.T) {
	bob, err := CreateUser()
	if err != nil {
		t.Fatalf("Error creating new user: %v", err)
	}
	pubKey, err := bob.PublicKey()
	if err != nil {
		t.Fatalf("Error creating public key for bob: %v", err)
	}

	bobPub, err := FromPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Error creating public bob from public key: %v", err)
	}

	testMsg := []byte("This is a test from dlc22")

	cipher1, err := bobPub.Encrypt(testMsg)
	if err != nil {
		t.Fatalf("Got an error on encrypt: %v", err)
	}

	cipher2, err := bob.Encrypt(testMsg)
	if err != nil {
		t.Fatalf("Got an error on encrypt: %v", err)
	}

	if bytes.Equal(cipher1, cipher2) {
		t.Fatalf("Ciphers from bob and public bob match, they should not")
	}

	if _, err := bobPub.Decrypt(cipher1); err != ErrCannotDecrypt {
		t.Fatalf("Expected an error, got none")
	}

	plain, err := bob.Decrypt(cipher1)
	if err != nil {
		t.Fatalf("Got an error decrypting: %v", err)
	}
	if !bytes.Equal(testMsg, plain) {
		t.Fatalf("Did not receive correct decrypted message: %q", plain)
	}

	plain, err = bob.Decrypt(cipher2)
	if err != nil {
		t.Fatalf("Got an error decrypting: %v", err)
	}
	if !bytes.Equal(testMsg, plain) {
		t.Fatalf("Did not receive correct decrypted message: %q", plain)
	}
}
