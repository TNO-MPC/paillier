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

package paillier

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateKey(t *testing.T) {
	_, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
}

func TestInterfaceType(t *testing.T) {
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	foo := func(e Encrypter) {
		t.Logf("Successfully created interface %v", e)
	}

	foo(sk)
	foo(&sk.PublicKey)

	pcbuf, err := NewPrecomputeBuffer(sk.PublicKey, 4, 1, true)
	if err != nil {
		t.Fatalf("Error making buffer: %v", err)
	}
	defer pcbuf.Close()

	foo(pcbuf)
}

func TestEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	pk := sk.PublicKey
	m := big.NewInt(42)
	ct := pk.Encrypt(m)

	decryptedM := sk.Decrypt(ct)

	assert.True(m.Cmp(decryptedM) == 0, "Dec(Enc(m)) != m")
}

func TestAdd(t *testing.T) {
	assert := assert.New(t)
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	pk := sk.PublicKey

	m1 := big.NewInt(10)
	m2 := big.NewInt(15)
	sum := new(big.Int).Add(m1, m2)

	ct1 := pk.Encrypt(m1)

	ct2 := pk.Encrypt(m2)

	ctSum := pk.Add(ct1, ct2)

	decryptedSum := sk.Decrypt(ctSum)

	assert.True(decryptedSum.Cmp(sum) == 0, "Encrypted addition fails.")
}

func TestAddTo(t *testing.T) {
	assert := assert.New(t)
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	pk := sk.PublicKey

	m1 := big.NewInt(10)
	m2 := big.NewInt(15)
	sum := new(big.Int).Add(m1, m2)

	ct1 := pk.Encrypt(m1)

	ct2 := pk.Encrypt(m2)

	pk.AddTo(ct1, ct2)

	decryptedSum := sk.Decrypt(ct1)

	assert.True(decryptedSum.Cmp(sum) == 0, "Encrypted addition failed.")
}

func TestMul(t *testing.T) {
	assert := assert.New(t)
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	pk := sk.PublicKey

	m1 := big.NewInt(6)
	m2 := big.NewInt(13)
	product := new(big.Int).Mul(m1, m2)

	ct := pk.Encrypt(m1)

	ctProd := pk.Mul(ct, m2)

	decryptedProduct := sk.Decrypt(ctProd)

	assert.True(decryptedProduct.Cmp(product) == 0, "Multiplication with plaintext value failed.")
}
func TestRandomize(t *testing.T) {
	assert := assert.New(t)
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}

	pk := sk.PublicKey
	m := big.NewInt(42)
	ct := pk.Encrypt(m)

	ctRandomized := pk.Randomize(ct)

	decryptedM := sk.Decrypt(ctRandomized)

	assert.True(m.Cmp(decryptedM) == 0, "Randomization failed.")
}
