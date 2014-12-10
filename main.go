package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

var key []byte
var headers = make(map[string]string)

func init() {
	size := 32
	key = make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("Base64 AES-256 Key - %q\n", base64.StdEncoding.EncodeToString(key))
	headers["key"] = base64.StdEncoding.EncodeToString(key)
}

func decrypt() {
	inFile, err := os.Open("encrypted-file")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile("decrypted-file", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, inFile)
	reader := &cipher.StreamReader{S: stream, R: decoder}

	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. It you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the output.
}

func encrypt() {
	inFile, err := os.Open("plaintext-file")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile("encrypted-file", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	encoder := base64.NewEncoder(base64.StdEncoding, outFile)
	defer encoder.Close()
	writer := &cipher.StreamWriter{S: stream, W: encoder}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		panic(err)
	}

	// Note that this example is simplistic in that it omits any
	// authentication of the encrypted data. It you were actually to use
	// StreamReader in this manner, an attacker could flip arbitrary bits in
	// the decrypted result.
}

func main() {
	encrypt()
	decrypt()

	pubKey, err := openPubKey()
	privKey, err := openPrivKey()

	if privKey.N.Cmp(pubKey.N) == 0 {
		fmt.Println("Public Key and Private Key match")
	}

	gpgEncrypt(pubKey)
	gpgDecrypt(privKey)

	inFile, err := os.Open("decrypted-file")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	buf := bufio.NewReader(inFile)
	out, err := buf.ReadString(byte(0))
	fmt.Print(out)

}
