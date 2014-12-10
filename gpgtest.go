package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/sha3"
)

//A fake static time for when keys are (were) created
var KeyDate time.Time = time.Date(1979, time.April, 10, 14, 15, 0, 0, time.FixedZone("VET", -16200))

func gpgEncrypt(rsaPubKey *rsa.PublicKey) {

	aesKey := make([]byte, packet.CipherAES256.KeySize())
	rand.Read(aesKey)

	pubKey := packet.NewRSAPublicKey(KeyDate, rsaPubKey)
	config := &packet.Config{
		DefaultHash:   crypto.SHA3_512,
		DefaultCipher: packet.CipherAES256,
	}

	inFile, err := os.Open("plaintext-file")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	outFile, err := os.OpenFile("encrypted-file", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	outArmor, err := armor.Encode(outFile, "SSH-CRYPT-MESSAGE", make(map[string]string))
	if err != nil {
		panic(err)
	}
	defer outArmor.Close()

	err = packet.SerializeEncryptedKey(outArmor, pubKey, packet.CipherAES256, aesKey, config)
	if err != nil {
		panic(err)
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
	writer, err := packet.SerializeLiteral(encryptedData, hints.IsBinary, hints.FileName, epochSeconds)
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

func prompter(keys []openpgp.Key, symmetric bool) (passphrase []byte, err error) {
	return
}

func gpgDecrypt(rsaPrivKey *rsa.PrivateKey) {

	privKey := packet.NewRSAPrivateKey(KeyDate, rsaPrivKey)
	config := &packet.Config{
		DefaultHash:   crypto.SHA3_512,
		DefaultCipher: packet.CipherAES256,
	}

	inFile, err := os.Open("encrypted-file")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	outFile, err := os.OpenFile("decrypted-file", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

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
