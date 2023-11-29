// This file shows how to verify messages with ECDSA
package main

import (
	"fmt"
	"log"

	"github.com/danielost/ecdsa/internal/ecdsa"
)

func main() {
	// Suppose you have a signature, a message and the public key needed to verify the signature
	base := 16
	message := "Send $100 to Bob now!"
	sPublicKey := "3fb8197d8566fde03a1b7df6ea4af1b6696f08b5d0416fa5fa82cbcdddeaad93:6a53606718d9971c9a1a264dd951617e7c3e4d8af8ab19a7d5944425c2904ab7"
	sSignature := "444e0d98cefbd664dd5e6d90da3b9b85658b600d0a46ee3656a9f5129c966355:e333e97201c5dd2f62b97c80a4cf831927790897699d57dadf1621323519bc18"

	// Deserialize the public key
	publicKey, err := ecdsa.DeserializePublicKey(sPublicKey, base)
	if err != nil {
		log.Fatal(err)
	}

	// Deserialize the signature
	signature, err := ecdsa.DeserializeSignature(sSignature, base)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature
	verified := ecdsa.Verify([]byte(message), publicKey, signature)

	if verified {
		fmt.Println("Signature is verified!")
	} else {
		fmt.Println("Signature is not verified :(")
	}
}
