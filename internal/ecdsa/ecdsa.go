package ecdsa

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/danielost/ecpoint-wrappers/pkg/ecwrapper"
)

var once = &sync.Once{}
var ecw *ecwrapper.ECWrapper

type KeyPair struct {
	privateKey *big.Int
	publicKey  *ecwrapper.ECPoint
}

func (kp *KeyPair) PublicKey() *ecwrapper.ECPoint {
	return kp.publicKey
}

func (kp *KeyPair) PrivateKey() *big.Int {
	return kp.privateKey
}

func getECWrapper() *ecwrapper.ECWrapper {
	once.Do(func() {
		ecw = ecwrapper.NewECWrapper(elliptic.P256())
	})
	return ecw
}

func GenerateKeys() (*KeyPair, error) {
	curve := getECWrapper()
	N := curve.Params().N
	G := curve.GetBasePointG()
	sKey, err := rand.Int(rand.Reader, N)
	if err != nil {
		return nil, err
	}
	pKey := curve.ScalarMult(sKey, G)
	return &KeyPair{sKey, pKey}, nil
}
