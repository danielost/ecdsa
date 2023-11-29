package ecdsa

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/danielost/ecdsa/internal/ecdsa"
	"github.com/danielost/ecpoint-wrappers/pkg/ecwrapper"
)

type Test struct {
	name       string
	sign       []byte
	verify     []byte
	wantErr    bool
	privateKey *big.Int
	publicKey  *ecwrapper.ECPoint
}

func TestSign(t *testing.T) {
	kp1, err := ecdsa.GenerateKeys()
	if err != nil {
		t.Error("error occured while generating a key pair")
		return
	}
	kp2, err := ecdsa.GenerateKeys()
	if err != nil {
		t.Error("error occured while generating a key pair")
		return
	}

	tests := []Test{
		{"sign and verify the same msg with correct public key", []byte("send $100 to Bob"), []byte("send $100 to Bob"), false, kp1.PrivateKey(), kp1.PublicKey()},
		{"sign and verify different msgs with correct public key", []byte("send $100 to Bob"), []byte("send $200 to Bob"), true, kp1.PrivateKey(), kp1.PublicKey()},
		{"sign and verify the same msg with wrong public key", []byte("send $100 to Bob"), []byte("send $100 to Bob"), true, kp1.PrivateKey(), kp2.PublicKey()},
	}

	for i := 0; i < 1000; i++ {
		str := []byte(randSeq(1000))
		tests = append(tests, Test{"sign and verify the same random msg with correct public key", str, str, false, kp1.PrivateKey(), kp1.PublicKey()})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := ecdsa.Sign(tt.sign, tt.privateKey)
			if err != nil {
				t.Error("error occured while signing a message")
				return
			}
			verified := ecdsa.Verify(tt.verify, tt.publicKey, sig)
			if (verified == false) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
