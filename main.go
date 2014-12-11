package main

import (
	"flag"
	"os"
	"path"
)

var inFilePath string
var outFilePath string
var pubKeyPath string
var privKeyPath string
var doDecrypt bool

func init() {
	flag.StringVar(&inFilePath, "in", "-", "Input file")
	flag.StringVar(&outFilePath, "out", "-", "Output file")
	flag.StringVar(&pubKeyPath, "pubKey", path.Join(os.Getenv("HOME"), ".ssh/id_rsa.pub"), "Public Key file (Encrypting)")
	flag.StringVar(&privKeyPath, "privKey", path.Join(os.Getenv("HOME"), ".ssh/id_rsa"), "Private Key file (Decrypting)")
	flag.BoolVar(&doDecrypt, "d", false, "Decrypt file instead of encrypting")
}

func main() {

	flag.Parse()
	var err error

	var inFile *os.File
	if inFilePath == "-" {
		inFile = os.Stdin
	} else {
		inFile, err = os.Open(inFilePath)
		if err != nil {
			panic(err)
		}
	}
	defer inFile.Close()

	var outFile *os.File
	if outFilePath == "-" {
		outFile = os.Stdout
	} else {
		outFile, err = os.OpenFile("encrypted-file", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			panic(err)
		}
	}
	defer outFile.Close()

	if doDecrypt {
		privKey, err := openPrivKey()
		if err != nil {
			panic(err)
		}
		gpgDecrypt(privKey, inFile, outFile)
		return
	}

	pubKey, err := openPubKey()
	if err != nil {
		panic(err)
	}
	gpgEncrypt(pubKey, inFile, outFile)

}
