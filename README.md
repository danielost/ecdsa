# ECDSA in Go
ECDSA implementation in Go. Task №8 for the Cryptography for Developers course.

## Setup
Execute the following command first:

```bash
go get github.com/danielost/ecdsa
```

Then simply add the following import to your Go code:

```go
import (
  // Importing the ECDSA package
  "github.com/danielost/ecdsa/internal/ecdsa"
)
```

## API description
ECDSA:
- `GenerateKeys() (*KeyPair, error)` - Generates a new ECDSA key pair
- `Sign(message []byte, privateKey *big.Int) (*Signature, error)` - Signs a message using the private key
- `Verify(message []byte, publicKey *ecwrapper.ECPoint, sig *Signature) bool` - Verifies a message using the public key

Convenience methods:
- `SerializePublicKey(publicKey *ecwrapper.ECPoint, base int) string` - Serializes a public key
- `DeserializePublicKey(publicKey string, base int) (*ecwrapper.ECPoint, error)` - Deserializes a public key
- `SerializePrivateKey(privateKey *big.Int, base int) string` - Serializes a private key
- `DeserializePrivateKey(privateKey string, base int) (*big.Int, error)` - Deserializes a private key
- `SerializeSignature(signature *Signature, base int) string` - Serializes a signature
- `DeserializeSignature(signature string, base int) (*Signature, error)` - Deserializes a signature

## Examples

`Examples` folder contains guides on how to generate keys and sign and verify messages.

Example of signing a message:
```go
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
```

## Testing
To run the tests, clone the repository and execute the following command:
```bash
go test ./...
```
or (for the detailed view):
```bash
go test -v ./...
```
