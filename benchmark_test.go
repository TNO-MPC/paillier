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

func BenchmarkEncrypt(b *testing.B) {
	sk, err := GenerateKey(2048)
	if err != nil {
		b.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pk.Encrypt(big.NewInt(42))
	}
}
func BenchmarkDecrypt(b *testing.B) {
	assert := assert.New(b)
	sk, err := GenerateKey(2048)
	if err != nil {
		b.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	m := big.NewInt(42)
	ct := pk.Encrypt(m)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptedM := sk.Decrypt(ct)
		assert.True(m.Cmp(decryptedM) == 0, "Dec(Enc(m)) != m")
	}
}

func BenchmarkAdd(b *testing.B) {
	assert := assert.New(b)
	sk, err := GenerateKey(2048)
	if err != nil {
		b.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	m := big.NewInt(1)
	ct := pk.Encrypt(m)
	accumulator := pk.Encrypt(big.NewInt(0))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		accumulator = pk.Add(accumulator, ct)
	}
	decryptedM := sk.Decrypt(accumulator)
	assert.True(big.NewInt(int64(b.N)).Cmp(decryptedM) == 0, "Encrypted addition failed")
}

func BenchmarkRandomize(b *testing.B) {
	assert := assert.New(b)
	sk, err := GenerateKey(2048)
	if err != nil {
		b.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	m := big.NewInt(42)
	ct := pk.Encrypt(m)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct = pk.Randomize(ct)
	}
	decryptedM := sk.Decrypt(ct)
	assert.True(m.Cmp(decryptedM) == 0, "Randomization failed")
}

func BenchmarkRandomizePrecomputed1000(b *testing.B) {
	assert := assert.New(b)
	sk, err := GenerateKey(2048)
	if err != nil {
		b.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	n := 1000
	pcbuf, err := NewPrecomputeBuffer(pk, n, 1, true)
	if err != nil {
		b.Fatalf("Error making buffer: %v", err)
	}
	m := big.NewInt(42)
	ct := pk.Encrypt(m)
	b.ResetTimer()
	for i := 0; i < n; i++ {
		ct = pcbuf.Randomize(ct)
	}
	decryptedM := sk.Decrypt(ct)
	assert.True(m.Cmp(decryptedM) == 0, "Randomization failed")
}
