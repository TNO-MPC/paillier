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
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPrecomputeBuffer1(t *testing.T) {
	assert := assert.New(t)
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	pcbuf, err := NewPrecomputeBuffer(pk, 4, 1, true)
	if err != nil {
		t.Fatalf("Error making buffer: %v", err)
	}
	defer pcbuf.Close()
	m := big.NewInt(42)
	ct := pk.PartiallyEncrypt(m)
	randomized1 := pcbuf.Randomize(ct)
	randomized2 := pcbuf.Randomize(ct)

	// Check whether we don't accidentally make a silly mistake
	assert.NotEqual(0, randomized1.Cmp(randomized2), "randomized1 == randomized2")

	// Just in case, also check whether decryption works in both cases
	assert.Equal(sk.Decrypt(randomized1).Uint64(), uint64(42), "Decryption failed after randomize (1)")
	assert.Equal(sk.Decrypt(randomized2).Uint64(), uint64(42), "Decryption failed after randomize (2)")

	// Just in case, also check that the buffer keeps computing new values
	for i := 0; i != 100; i++ {
		assert.NotNil(pcbuf.Get())
	}
}

func TestPrecomputeBufferClose(t *testing.T) {
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	pcbuf, err := NewPrecomputeBuffer(pk, 4, 1, true)
	if err != nil {
		t.Fatalf("Error making buffer: %v", err)
	}
	time.Sleep(1 * time.Second)

	// Testing waitgroup
	// If test timeout occurs, then goroutines are dangling.
	pcbuf.Close()
}

func TestPrecomputeBufferPrematureClose(t *testing.T) {
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	pcbuf, err := NewPrecomputeBuffer(pk, 10000, 4, false)
	if err != nil {
		t.Fatalf("Error making buffer: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Should close quickly, ending all precomputers
	t1 := time.Now()
	pcbuf.Close()
	t2 := time.Now()
	assert.Greater(t, int64(500), int64(t2.Sub(t1).Milliseconds()))

	// Drain the buffer
	for len(pcbuf.rnBuffer) != 0 {
		pcbuf.Get()
	}

	// Should not crash or hang on Get, but return quickly
	assert.Nil(t, pcbuf.Get())

	// Should still randomize numbers
	assert.NotNil(t, pcbuf.Randomize(big.NewInt(1)))
}

func TestEncryptDecryptWithPrecomputation(t *testing.T) {
	assert := assert.New(t)
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	pk := sk.PublicKey
	pcbuf, err := NewPrecomputeBuffer(pk, 4, 1, true)
	if err != nil {
		t.Fatalf("Error making buffer: %v", err)
	}
	defer pcbuf.Close()
	m := big.NewInt(42)
	ct := pcbuf.Encrypt(m)

	assert.Equal(sk.Decrypt(ct).Uint64(), uint64(42), "Dec(Enc(m)) != m (precompute)")
}

func TestPrecomputationWithWait1(t *testing.T) {
	testPrecomputation(t, true, 1)
}

func TestPrecomputationWithoutWait1(t *testing.T) {
	testPrecomputation(t, false, 1)
}

func TestPrecomputationWithWaitNumCPU(t *testing.T) {
	testPrecomputation(t, true, runtime.NumCPU())
}

func TestPrecomputationWithoutWaitNumCPU(t *testing.T) {
	testPrecomputation(t, false, runtime.NumCPU())
}

func testPrecomputation(t *testing.T, waitForPrecomputation bool, nProc int) {
	// Yes, this is a benchmark disguised as a test ;)
	// TODO: make proper benchmark of this
	sk, err := GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
	t.Logf("Done generating key-pair")
	pk := sk.PublicKey
	n := 500
	if testing.Short() {
		n = 10
	}
	t.Logf("Creating precompute buffer of length %d, using %d goroutines", n, nProc)
	pcbuf, err := NewPrecomputeBuffer(pk, n, nProc, waitForPrecomputation)
	if err != nil {
		t.Fatalf("Error making buffer: %v", err)
	}
	defer pcbuf.Close()
	t.Logf("Done creating precompute buffer.")

	// here, the buffer should be full if waitForPrecomputation is true
	if waitForPrecomputation {
		assert.Equal(t, n, len(pcbuf.rnBuffer))
	}

	m := big.NewInt(42)

	t.Logf("Encrypting %d values", n)
	cts := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		cts[i] = pcbuf.Encrypt((m))
	}
	t.Logf("Done.")
}
