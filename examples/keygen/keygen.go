// This file shows how to generate ECDSA keys
package main

import (
	"fmt"
	"log"

	"github.com/danielost/ecdsa/internal/ecdsa"
)

func main() {
	// Generate the key pair
	keyPair, err := ecdsa.GenerateKeys()
	if err != nil {
		log.Fatal(err)
	}

	// Extract the keys
	publicKey := keyPair.PublicKey()
	privateKey := keyPair.PrivateKey()

	// You can serialize the key pair for more convenient use
	base := 16
	sPublicKey := ecdsa.SerializePublicKey(publicKey, base)
	sPrivateKey := ecdsa.SerializePrivateKey(privateKey, base)

	fmt.Println(sPublicKey)
	fmt.Println(sPrivateKey)
}
