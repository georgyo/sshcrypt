package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/totallylegitbiz/sshcrypt/gopass"

	"golang.org/x/crypto/ssh"
)

// ParsePrivateKey returns a private key from a PEM encoded private key. It
// supports RSA (PKCS#1)
func ParsePrivateRSAKey(pemBytes []byte) (key *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		if procType, ok := block.Headers["Proc-Type"]; ok && procType == "4,ENCRYPTED" {
			keyPass, err := gopass.GetPass("Password: ")
			if err != nil {
				panic(err)
			}
			decryptedPemBtyes, err := x509.DecryptPEMBlock(block, []byte(keyPass))
			if err != nil {
				panic(err)
			}
			return x509.ParsePKCS1PrivateKey(decryptedPemBtyes)
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func ParseAuthorizedRSAKey(in []byte) (out *rsa.PublicKey, err error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(in)
	if err != nil {
		return nil, err
	}
	if key.Type() != "ssh-rsa" {
		return nil, fmt.Errorf("%q is not an rsa key", key.Type())
	}
	retTyp := reflect.TypeOf(out)
	retVal := reflect.ValueOf(key).Convert(retTyp)
	out = retVal.Interface().(*rsa.PublicKey)
	return out, nil
}

func openPubKey(path string) (out []*rsa.PublicKey, err error) {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, err := ParseAuthorizedRSAKey(scanner.Bytes())
		if err != nil {
			fmt.Printf("Could not read key")
			continue
		}
		out = append(out, key)

	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	return out, err

}

func openPrivKey(path string) (key *rsa.PrivateKey, err error) {
	file, err := os.Open(path)
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

	return ParsePrivateRSAKey(buf)

}
