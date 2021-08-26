# TNO MPC Lab - Paillier

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package paillier is part of the TNO Go Toolbox.

*Limitations in (end-)use: the content of this repository may solely be used for applications that comply with international export control laws.*

## Paillier cryptosystem

This library is an implementation of the Paillier homomorphic encryption scheme in Go.

## Usage

To generate a Paillier private key, use GenerateKey:
```go
	sk, err := paillier.GenerateKey(2048)
	if err != nil {
		t.Fatalf("Error generating key: %v", err)
	}
```

You can extract the public key from the returned structure, and send it safely to others.
```go
	pk := sk.PublicKey
```

To encrypt data, use the `Encrypt` method on a public or private key.
You can also compute with encrypted data by using the `Add` and `Mul` methods.
```go
	m1 := big.NewInt(10)
	m2 := big.NewInt(15)
	sum := new(big.Int).Add(m1, m2)

	ct1 := pk.Encrypt(m1)

	ct2 := pk.Encrypt(m2)

	ctSum := pk.Add(ct1, ct2)

	decryptedSum := sk.Decrypt(ctSum)

	// decryptedSum.Cmp(sum) == 0
```

The Paillier cryptosystem allows you to randomize ciphertexts.
This is necessary, since otherwise, certain meaningful values (e.g. 0) would be easy to
recognize if they result from a computation, even by persons without the private key.
You can use the `Randomize` method to re-randomize any ciphertext.

Since random data is expensive in terms of time, the package comes with a facility to
pre-compute randomness. If you need to encrypt large data sets, but not very often, you
can speed up encryption by keeping a buffer of randomness that is replenished after you
are done with encrypting the data set. See documentation on the `NewPrecomputeBuffer`
function for information on how to use it.

Both the precompute buffer and the public key implement the Encrypter interface, which
you can use in your software to transparently work with either plain keys or keys with
a buffer attached.

