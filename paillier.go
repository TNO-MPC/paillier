// Copyright 2021 TNO
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A Paillier implementation in Go with some optimizations.
// This includes choosing g = n + 1. More documentation required.

package paillier

import (
	"crypto/rand"
	"math/big"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// Encrypter is an interface for additively homomorphic encryption schemes.
type Encrypter interface {
	// Randomize (re-)randomizes an encrypted value
	Randomize(ciphertext *big.Int) *big.Int
	// Encrypt encrypts a message (big.Int)
	Encrypt(plaintext *big.Int) *big.Int
	// PartiallyEncrypt does the first part of the encryption, so that the
	// (computationally expensive) randomization can be done at a later time.
	PartiallyEncrypt(plaintext *big.Int) *big.Int
	// Add adds two encrypted values and returns the encrypted sum.
	Add(ciphertextA, ciphertextB *big.Int) *big.Int
	// AddTo adds b to the Encrypted value a (and also returns it).
	AddTo(ciphertextA, ciphertextB *big.Int) *big.Int
	// Mul multiplies the plaintext value b with the encrypted value a and returns the result.
	Mul(ciphertextA, plaintextB *big.Int) *big.Int
}

// PublicKey is a Paillier public key and implements the Encrypter interface
type PublicKey struct {
	N      *big.Int
	N2     *big.Int // cached value of N^2
	Nplus1 *big.Int // cached value of N + 1
	bits   int      // Number of bits of N
}

// PrivateKey is a Paillier private key
type PrivateKey struct {
	PublicKey
	Lambda *big.Int
	X      *big.Int // Cached value for faster decryption
}

//lcm computes the least common multiple
func lcm(a, b *big.Int) *big.Int {
	t := new(big.Int)
	t.Div(t.Mul(a, b), new(big.Int).GCD(nil, nil, a, b))
	return t
}

// Just use the default randomness provider of crypto/rand.
var random = rand.Reader

// GenerateKey generates a random Paillier private key
func GenerateKey(bits int) (priv *PrivateKey, err error) {
	var p, q *big.Int
	n := new(big.Int)
	for {
		p, _ = rand.Prime(random, bits>>1)
		q, _ = rand.Prime(random, bits>>1)
		n.Mul(p, q)
		if n.Bit(bits-1) == 1 && p.Cmp(q) != 0 {
			break
		}
	}
	lambda := lcm(p.Sub(p, bigOne), q.Sub(q, bigOne))
	np1 := new(big.Int).Add(n, bigOne)
	n2 := new(big.Int).Mul(n, n)
	x := new(big.Int)
	x.ModInverse(x.Div(x.Sub(x.Exp(np1, lambda, n2), bigOne), n), n)
	priv = &PrivateKey{PublicKey{n, n2, np1, bits}, lambda, x}
	return
}

// getRN computes r^N mod N^2
func (k *PublicKey) getRN() *big.Int {
	r, _ := rand.Int(random, k.N)
	return r.Exp(r, k.N, k.N2)
}

// Randomize randomizes an encrypted value.
func (k *PublicKey) Randomize(a *big.Int) *big.Int {
	rn := k.getRN()
	return rn.Mul(rn, a)
}

// Encrypt encrypts a message (big.Int).
func (k *PublicKey) Encrypt(m *big.Int) *big.Int {
	return k.Randomize(k.PartiallyEncrypt(m))
}

// PartiallyEncrypt does the first part of the encryption, so that the
// (computationally expensive) randomization can be done at a later time.
func (k *PublicKey) PartiallyEncrypt(m *big.Int) *big.Int {
	t := new(big.Int).Mul(k.N, m)
	t.Add(t, bigOne)
	return t.Mod(t, k.N2)
}

// Add adds two encrypted values and returns the encrypted sum.
func (k *PublicKey) Add(a, b *big.Int) *big.Int {
	t := new(big.Int).Mul(a, b)
	return t.Mod(t, k.N2)
}

// AddTo adds b to the Encrypted value a (and also returns it).
func (k *PublicKey) AddTo(a, b *big.Int) *big.Int {
	return a.Mod(a.Mul(a, b), k.N2)
}

// Mul multiplies the plaintext value b with the encrypted value a and returns the result.
func (k *PublicKey) Mul(a, b *big.Int) *big.Int {
	return new(big.Int).Exp(a, b, k.N2)
}

// Decrypt attempts to decrypt the provided cyphertext and returns the result.
func (k *PrivateKey) Decrypt(c *big.Int) *big.Int {
	t := new(big.Int)
	return t.Mod(t.Mul(t.Div(t.Sub(t.Exp(c, k.Lambda, k.N2), bigOne), k.N), k.X), k.N)
}
