// This file shows how to sign messages with ECDSA
package main

import (
	"fmt"
	"log"

	"github.com/danielost/ecdsa/internal/ecdsa"
)

func main() {
	// You can either generate a key pair or use previously generated keys.
	// See how to generate a key pair in ./examples/keygen/keygen.go.
	// Most likely, you will have your keys stored as strings. Use deserialization methods to convert them
	// to the required objects.
	base := 16
	sPrivateKey := "bb072d57567f800e4d0a00a0eba95e9f33b839b3b18728fc3000dfb2e4d9621d"
	// sPublicKey := "3fb8197d8566fde03a1b7df6ea4af1b6696f08b5d0416fa5fa82cbcdddeaad93:6a53606718d9971c9a1a264dd951617e7c3e4d8af8ab19a7d5944425c2904ab7"
	privateKey, err := ecdsa.DeserializePrivateKey(sPrivateKey, base)
	if err != nil {
		log.Fatal(err)
	}

	message := "Send $100 to Bob now!"
	signature, err := ecdsa.Sign([]byte(message), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// You can now serialize the signature along with the public key and save or send them
	sSignature := ecdsa.SerializeSignature(signature, base)

	fmt.Println(sSignature)
}
