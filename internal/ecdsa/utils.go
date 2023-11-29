package ecdsa

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/danielost/ecpoint-wrappers/pkg/ecwrapper"
)

func SerializePublicKey(publicKey *ecwrapper.ECPoint, base int) string {
	return ecwrapper.ECPointToString(publicKey, base)
}

func DeserializePublicKey(publicKey string, base int) (*ecwrapper.ECPoint, error) {
	return ecwrapper.StringToECPoint(publicKey, base)
}

func SerializePrivateKey(privateKey *big.Int, base int) string {
	return privateKey.Text(base)
}

func DeserializePrivateKey(privateKey string, base int) (*big.Int, error) {
	bi, ok := new(big.Int).SetString(privateKey, base)
	if !ok {
		return nil, fmt.Errorf("wrong base")
	}

	return bi, nil
}

func SerializeSignature(signature *Signature, base int) string {
	r := signature.r.Text(base)
	s := signature.s.Text(base)

	return r + ":" + s
}

func DeserializeSignature(signature string, base int) (*Signature, error) {
	sli := strings.Split(signature, ":")
	if len(sli) != 2 {
		return nil, fmt.Errorf("wrong signature format, must be <r:s>")
	}

	r, ok := new(big.Int).SetString(sli[0], base)
	if !ok {
		return nil, fmt.Errorf("wrong base for r")
	}

	s, ok := new(big.Int).SetString(sli[1], base)
	if !ok {
		return nil, fmt.Errorf("wrong base for s")
	}

	return NewSignature(r, s), nil
}
