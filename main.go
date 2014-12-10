package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	pubKey, err := openPubKey()
	privKey, err := openPrivKey()

	if privKey.N.Cmp(pubKey.N) == 0 {
		fmt.Println("Public Key and Private Key match")
	}

	//Reads plaintext-file and writes encrypted-file
	gpgEncrypt(pubKey)

	//Reads encrypted-file and writes decrypted-file
	gpgDecrypt(privKey)

	// Output the decrypted file
	inFile, err := os.Open("decrypted-file")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	buf := bufio.NewReader(inFile)
	out, err := buf.ReadString(byte(0))
	fmt.Print(out)

}
