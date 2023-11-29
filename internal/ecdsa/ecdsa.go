package ecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"math/big"
	"sync"

	// Import ECPoint wrapper package for elliptic curve operations
	"github.com/danielost/ecpoint-wrappers/pkg/ecwrapper"
)

var once = &sync.Once{}
var ecw *ecwrapper.ECWrapper

// Holds a private key and its corresponding public key
type KeyPair struct {
	privateKey *big.Int
	publicKey  *ecwrapper.ECPoint
}

// Holds the ECDSA signature components (r and s)
type Signature struct {
	r, s *big.Int
}

// Creates a new KeyPair from a private key and public key
func NewKeyPair(privateKey *big.Int, publicKey *ecwrapper.ECPoint) *KeyPair {
	return &KeyPair{
		privateKey,
		publicKey,
	}
}

// Creates a new Signature from signature components (r and s)
func NewSignature(r, s *big.Int) *Signature {
	return &Signature{
		r,
		s,
	}
}

// Extracts the public key from the KeyPair
func (kp *KeyPair) PublicKey() *ecwrapper.ECPoint {
	return kp.publicKey
}

// Extracts the private key from the KeyPair
func (kp *KeyPair) PrivateKey() *big.Int {
	return kp.privateKey
}

// Initializes the ECWrapper instance if not initialized yet.
// Otherwise returns previously initialized instance
func getECWrapper() *ecwrapper.ECWrapper {
	once.Do(func() {
		ecw = ecwrapper.NewECWrapper(elliptic.P256())
	})

	return ecw
}

// Generates a new ECDSA key pair
func GenerateKeys() (*KeyPair, error) {
	curve := getECWrapper()
	N := curve.Params().N
	G := curve.GetBasePointG()

	// Generate a random private key
	privateKey, err := rand.Int(rand.Reader, N)
	if err != nil {
		return nil, err
	}

	// Compute the corresponding public point (public key)
	publicKey := curve.ScalarMult(privateKey, G)

	return NewKeyPair(privateKey, publicKey), nil
}

// Signs a message using the private key
func Sign(message []byte, privateKey *big.Int) (*Signature, error) {
	curve := getECWrapper()
	N := curve.Params().N
	G := curve.GetBasePointG()

	// Generate a random nonce
	nonce, err := rand.Int(rand.Reader, N)
	if err != nil {
		return nil, err
	}

	// Compute the message hash
	digest := sha256.Sum256([]byte(message))
	R := curve.ScalarMult(nonce, G)
	r, _ := R.Params()
	r.Mod(r, N)

	// If r is zero, go back
	if r.Cmp(big.NewInt(0)) == 0 {
		log.Println("trying to sign again")
		return Sign(message, privateKey)
	}

	kInverse := new(big.Int).ModInverse(nonce, N)
	hM := new(big.Int).SetBytes(digest[:])
	hM.Add(hM, new(big.Int).Mul(privateKey, r))
	s := new(big.Int).Mul(kInverse, hM)
	s.Mod(s, N)

	// If s is zero, go back
	if s.Cmp(big.NewInt(0)) == 0 {
		log.Println("trying to sign again")
		return Sign(message, privateKey)
	}

	return NewSignature(r, s), nil
}

// Verifies a message using the public key
func Verify(message []byte, publicKey *ecwrapper.ECPoint, sig *Signature) bool {
	curve := getECWrapper()
	N := curve.Params().N
	G := curve.GetBasePointG()
	r, s := sig.r, sig.s

	// Check if r and s are within the valid range
	if !inRange(r) || !inRange(s) {
		return false
	}

	// Compute the message hash
	digest := sha256.Sum256(message)
	sInverse := new(big.Int).ModInverse(s, N)
	c := new(big.Int).Mod(sInverse, N)
	hM := new(big.Int).SetBytes(digest[:])
	u1 := new(big.Int).Mul(hM, c)
	u1.Mod(u1, N)

	u2 := new(big.Int).Mul(r, c)
	u2.Mod(u2, N)

	R1 := curve.ScalarMult(u1, G)
	R2 := curve.ScalarMult(u2, publicKey)
	R := curve.Add(R1, R2)
	x, _ := R.Params()
	x.Mod(x, N)

	// Verify the signature by comparing r and x
	return r.Cmp(x) == 0
}

// Checks if a big int is in the appropriate range
func inRange(bi *big.Int) bool {
	curve := getECWrapper()
	lo, hi := big.NewInt(0), curve.Params().N
	if bi.Cmp(lo) == -1 || bi.Cmp(hi) >= 0 {
		log.Println("big int out of range")
		return false
	}
	return true
}
