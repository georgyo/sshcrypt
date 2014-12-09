package main

import (
	"crypto"
	"crypto/rsa"
	"io"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/sha3"
)

func gpgEnc(key *rsa.PublicKey, out io.Writer) (in io.WriteCloser, err error) {
	var rcpts []*openpgp.Entity
	rcpts = append(rcpts, &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(time.Now(), key),
	})

	config := &packet.Config{
		DefaultHash:   crypto.SHA3_512,
		DefaultCipher: packet.CipherAES256,
	}

	return openpgp.Encrypt(out, rcpts, nil, nil, config)
}
