// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"time"

	_ "crypto/sha256"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

//A fake static time for when key's are (were) created
var KeyDate time.Time = time.Date(1979, time.April, 10, 14, 15, 0, 0, time.FixedZone("VET", -16200))

var config = &packet.Config{
	DefaultHash:            crypto.SHA256,
	DefaultCipher:          packet.CipherAES256,
	DefaultCompressionAlgo: packet.CompressionZLIB,
	CompressionConfig:      &packet.CompressionConfig{Level: 7},
}

func prompter(keys []openpgp.Key, symmetric bool) (passphrase []byte, err error) {
	return
}

func gpgEncrypt(rsaPubKeys []*rsa.PublicKey, inFile io.Reader, outFile io.Writer) {

	aesKey := make([]byte, packet.CipherAES256.KeySize())
	rand.Read(aesKey)

	outArmor, err := armor.Encode(outFile, "SSH-CRYPT-MESSAGE", make(map[string]string))
	if err != nil {
		panic(err)
	}
	defer outArmor.Close()

	if len(rsaPubKeys) == 0 {
		panic("No keys to use")
	}

	for _, rsaPubKey := range rsaPubKeys {
		pubKey := packet.NewRSAPublicKey(KeyDate, rsaPubKey)

		err = packet.SerializeEncryptedKey(outArmor, pubKey, packet.CipherAES256, aesKey, config)
		if err != nil {
			panic(err)
		}
	}

	encryptedData, err := packet.SerializeSymmetricallyEncrypted(outArmor, packet.CipherAES256, aesKey, config)
	if err != nil {
		panic(err)
	}
	defer encryptedData.Close()

	hints := &openpgp.FileHints{}
	var epochSeconds uint32
	if !hints.ModTime.IsZero() {
		epochSeconds = uint32(hints.ModTime.Unix())
	}

	compressedData, err := packet.SerializeCompressed(encryptedData, config.DefaultCompressionAlgo, config.CompressionConfig)
	if err != nil {
		panic(err)
	}
	defer compressedData.Close()

	writer, err := packet.SerializeLiteral(compressedData, hints.IsBinary, hints.FileName, epochSeconds)
	if err != nil {
		panic(err)
	}
	defer writer.Close()

	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. It you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the decrypted result.
}

func gpgDecrypt(rsaPrivKey *rsa.PrivateKey, inFile io.Reader, outFile io.Writer) {

	privKey := packet.NewRSAPrivateKey(KeyDate, rsaPrivKey)

	armorBlock, err := armor.Decode(inFile)
	if err != nil {
		panic(err)
	}

	var keyRing openpgp.EntityList
	keyRing = append(keyRing, &openpgp.Entity{
		PrivateKey: privKey,
		PrimaryKey: packet.NewRSAPublicKey(KeyDate, rsaPrivKey.Public().(*rsa.PublicKey)),
	})

	md, err := openpgp.ReadMessage(armorBlock.Body, keyRing, nil, config)
	if err != nil {
		panic(err)
	}

	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, md.UnverifiedBody); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. It you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.
}
