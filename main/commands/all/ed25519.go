package all

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/xtls/xray-core/main/commands/base"
)

var cmdEd25519 = &base.Command{
	UsageLine: `{{.Exec}} ed25519 [-i "private key seed (base64.RawURLEncoding)"] [--std-encoding]`,
	Short:     `Generate Ed25519 key pair`,
	Long: `
Generate Ed25519 key pair.

Random: {{.Exec}} ed25519

From private key seed: {{.Exec}} ed25519 -i "private key seed (base64.RawURLEncoding)"
For Std Encoding: {{.Exec}} ed25519 --std-encoding
`,
}

func init() {
	cmdEd25519.Run = executeEd25519
}

var inputSeed = cmdEd25519.Flag.String("i", "", "")
var inputStdEncoding = cmdEd25519.Flag.Bool("std-encoding", false, "")

func executeEd25519(cmd *base.Command, args []string) {
	var pubKey ed25519.PublicKey
	var privKey ed25519.PrivateKey
	var err error

	if *inputSeed != "" {
		decoder := base64.RawURLEncoding
		if *inputStdEncoding {
			decoder = base64.StdEncoding
		}

		seedBytes, err := decoder.DecodeString(*inputSeed)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: failed to decode private key seed:", err)
			return
		}

		if len(seedBytes) != ed25519.SeedSize {
			fmt.Fprintf(os.Stderr, "ERROR: invalid private key seed size: expected %d bytes, got %d\n", ed25519.SeedSize, len(seedBytes))
			return
		}

		privKey = ed25519.NewKeyFromSeed(seedBytes)
		pubKey = privKey.Public().(ed25519.PublicKey)

	} else {
		pubKey, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR: failed to generate Ed25519 key pair:", err)
			return
		}
	}

	privateKeySeed := privKey.Seed()
	publicKey := pubKey

	encoder := base64.RawURLEncoding
	if *inputStdEncoding {
		encoder = base64.StdEncoding
	}

	encodedPrivateKeySeed := encoder.EncodeToString(privateKeySeed)
	encodedPublicKey := encoder.EncodeToString(publicKey)

	output := fmt.Sprintf("Private Key: %s\nPublic Key: %s\n", encodedPrivateKeySeed, encodedPublicKey)

	fmt.Print(output)
}
