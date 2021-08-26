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
	"errors"
	"math/big"
	"sync"
)

// PrecomputeBuffer embeds PublicKey and thus implements the Encrypter interface,
type PrecomputeBuffer struct {
	PublicKey                // public key for which we generate random exponents
	rnBuffer  chan *big.Int  // buffer of precomputed random exponents
	closed    chan struct{}  // signal closure to the precomputers
	numProc   int            // number of processors/goroutines to use for filling the buffer
	wg        sync.WaitGroup // waitgroup to ensure proper goroutine cleanup
}

// NewPrecomputeBuffer creates a new PrecomputeBuffer for the specified public key and
// immediately starts filling this buffer using numProc processors (goroutines).
func NewPrecomputeBuffer(pk PublicKey, bufferSize int, numProc int, waitForCompletion bool) (*PrecomputeBuffer, error) {
	if numProc <= 0 {
		return nil, errors.New("Must use at least one precomputation process")
	}
	if bufferSize < 0 {
		return nil, errors.New("Buffer size can not be negative")
	}

	bufferFilled := make(chan bool)
	pcbuf := &PrecomputeBuffer{pk, make(chan *big.Int, bufferSize), make(chan struct{}), numProc, sync.WaitGroup{}}

	pcbuf.spawnPrecomputers(numProc, bufferFilled)

	if waitForCompletion {
		bufferFilled <- true // This blocks until someone reads from it
	}
	close(bufferFilled) // Release other computers reading this

	return pcbuf, nil
}

// Close stops the goroutines associated with the PrecomputeBuffer
func (pcbuf *PrecomputeBuffer) Close() {
	close(pcbuf.closed)
	pcbuf.wg.Wait()
}

// Get returns a new random exponent
func (pcbuf *PrecomputeBuffer) Get() *big.Int {
	select {
	case rn := <-pcbuf.rnBuffer:
		return rn
	case <-pcbuf.closed:
		return nil
	}
}

// spawnPrecomputers starts goroutines that fill the channel
func (pcbuf *PrecomputeBuffer) spawnPrecomputers(numProc int, bufferFilled chan bool) {
	for i := 0; i != numProc; i++ {
		pcbuf.wg.Add(1)
		go pcbuf.precompute(bufferFilled)
	}
}

// precompute tries to fill the pcbuf.rnBuffer channel with fresh random exponents
// the bufferFilled channel is used signal that the buffered channels has been
// filled
func (pcbuf *PrecomputeBuffer) precompute(bufferFilled chan bool) {
	defer pcbuf.wg.Done()
	fillingBuffer := true
	var newRN *big.Int
	for fillingBuffer {
		newRN = pcbuf.PublicKey.getRN()
		select {
		case pcbuf.rnBuffer <- newRN:
			// Managed to put something in the buffer
		case <-pcbuf.closed:
			return
		default:
			// This is reached only when `pcbuf.rnBuffer` is full
			// Read something from bufferFilled, this will trigger the wait
			// This channel is closed if nobody is waiting anymore
			<-bufferFilled
			fillingBuffer = false
		}
	}
	for {
		// When we exit this loop, we still need to process the last item
		// we weren't able to put into the channel, hence we'll start with
		// sending something to the channel here.
		select {
		case <-pcbuf.closed:
			return
		case pcbuf.rnBuffer <- newRN:
			newRN = pcbuf.PublicKey.getRN()
		}
	}
}

// Randomize randomizes an encrypted value and uses pre-computed random exponents to speed-up the computation.
func (pcbuf *PrecomputeBuffer) Randomize(a *big.Int) *big.Int {
	if rn := pcbuf.Get(); rn != nil {
		return rn.Mul(rn, a)
	}
	// PrecomputationBuffer is already closed
	// which makes this call erroneous
	// Nevertheless, returning nil is not legal, and may crash the program
	// so we opt for the slower method of using the PK for randomization
	return pcbuf.PublicKey.Randomize(a)
}

// Encrypt encrypts a message (big.Int) and uses pre-computed random exponents to speed-up the computation.
func (pcbuf *PrecomputeBuffer) Encrypt(m *big.Int) *big.Int {
	return pcbuf.Randomize(pcbuf.PublicKey.PartiallyEncrypt(m))
}
