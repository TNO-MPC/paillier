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

	"github.com/rs/zerolog/log"
)

type PrecomputeBufferMock struct {
	PublicKey          // public key for which we generate random exponents
	rn        *big.Int // fixed random number
}

// NewPrecomputeBufferMock creates a new PrecomputeBufferMock for the specified public key and
// reuses the same random value to mock a filled ProcomputeBuffer
func NewPrecomputeBufferMock(pk PublicKey) (*PrecomputeBufferMock, error) {
	log.Warn().Msg("===== INSECURE PrecomputeBufferMock in use, DO NOT IN PRODUCTION =====")

	rn := pk.getRN()
	pcbuf := &PrecomputeBufferMock{pk, rn}
	return pcbuf, nil
}

// Close stops the goroutines associated with the PrecomputeBuffer
func (pcbuf *PrecomputeBufferMock) Close() {
}

// Get returns a new random exponent
func (pcbuf *PrecomputeBufferMock) Get() *big.Int {
	return pcbuf.rn
}

// Randomize randomizes an encrypted value and uses pre-computed random exponents to speed-up the computation.
func (pcbuf *PrecomputeBufferMock) Randomize(a *big.Int) *big.Int {
	ret := &big.Int{}
	return ret.Mul(pcbuf.rn, a)
}

// Encrypt encrypts a message (big.Int) and uses pre-computed random exponents to speed-up the computation.
func (pcbuf *PrecomputeBufferMock) Encrypt(m *big.Int) *big.Int {
	return pcbuf.Randomize(pcbuf.PublicKey.PartiallyEncrypt(m))
}
