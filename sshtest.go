package main

import (
	"crypto/rsa"
	"os"

	//"github.com/k0kubun/pp"
)

func openPubKey() (out *rsa.PublicKey, err error) {
	file, err := os.Open("/Users/shammas/.ssh/id_rsa.pub")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		panic(err)
	}

	key, _, _, _, err := ParseAuthorizedKey(buf)
	if err != nil {
		panic(err)
	}

	return key, err

}

func openPrivKey() (key *rsa.PrivateKey, err error) {
	file, err := os.Open("/Users/shammas/.ssh/id_rsa")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		panic(err)
	}

	return ParsePrivateKey(buf)

}
