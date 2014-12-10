package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/ssh"
)

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = in[4 : 4+length]
	rest = in[4+length:]
	ok = true
	return
}

// parseRSA parses an RSA key according to RFC 4253, section 6.6.
func parseRSA(in []byte) (out *rsa.PublicKey, rest []byte, err error) {
	var w struct {
		E    *big.Int
		N    *big.Int
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	if w.E.BitLen() > 24 {
		return nil, nil, errors.New("ssh: exponent too large")
	}
	e := w.E.Int64()
	if e < 3 || e&1 == 0 {
		return nil, nil, errors.New("ssh: incorrect exponent")
	}

	key := &rsa.PublicKey{
		E: int(e),
		N: w.N,
	}
	return key, w.Rest, nil
}

// ParsePublicKey parses an SSH public key formatted for use in
// the SSH wire protocol according to RFC 4253, section 6.6.
func ParsePublicKey(in []byte) (out *rsa.PublicKey, err error) {
	algo, in, ok := parseString(in)
	if !ok {
		return nil, errors.New("ssh: short read")
	}
	if string(algo) != "ssh-rsa" {
		return nil, fmt.Errorf("ssh: unsupported key type %q", algo)
	}
	var rest []byte
	out, rest, err = parseRSA(in)
	if len(rest) > 0 {
		return nil, errors.New("ssh: trailing junk in public key")
	}

	return out, err
}

// parseAuthorizedKey parses a public key in OpenSSH authorized_keys format
// (see sshd(8) manual page) once the options and key type fields have been
// removed.
func parseAuthorizedKey(in []byte) (out *rsa.PublicKey, comment string, err error) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, "", err
	}
	key = key[:n]
	out, err = ParsePublicKey(key)
	if err != nil {
		return nil, "", err
	}
	comment = string(bytes.TrimSpace(in[i:]))
	return out, comment, nil
}

// ParseAuthorizedKeys parses a public key from an authorized_keys
// file used in OpenSSH according to the sshd(8) manual page.
func ParseAuthorizedKey(in []byte) (out *rsa.PublicKey, comment string, options []string, rest []byte, err error) {
	for len(in) > 0 {
		end := bytes.IndexByte(in, '\n')
		if end != -1 {
			rest = in[end+1:]
			in = in[:end]
		} else {
			rest = nil
		}

		end = bytes.IndexByte(in, '\r')
		if end != -1 {
			in = in[:end]
		}

		in = bytes.TrimSpace(in)
		if len(in) == 0 || in[0] == '#' {
			in = rest
			continue
		}

		i := bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if out, comment, err = parseAuthorizedKey(in[i:]); err == nil {
			return out, comment, options, rest, nil
		}

		// No key type recognised. Maybe there's an options field at
		// the beginning.
		var b byte
		inQuote := false
		var candidateOptions []string
		optionStart := 0
		for i, b = range in {
			isEnd := !inQuote && (b == ' ' || b == '\t')
			if (b == ',' && !inQuote) || isEnd {
				if i-optionStart > 0 {
					candidateOptions = append(candidateOptions, string(in[optionStart:i]))
				}
				optionStart = i + 1
			}
			if isEnd {
				break
			}
			if b == '"' && (i == 0 || (i > 0 && in[i-1] != '\\')) {
				inQuote = !inQuote
			}
		}
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i == len(in) {
			// Invalid line: unmatched quote
			in = rest
			continue
		}

		in = in[i:]
		i = bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if out, comment, err = parseAuthorizedKey(in[i:]); err == nil {
			options = candidateOptions
			return out, comment, options, rest, nil
		}

		in = rest
		continue
	}

	return nil, "", nil, nil, errors.New("ssh: no key found")
}

// ParsePrivateKey returns a private key from a PEM encoded private key. It
// supports RSA (PKCS#1)
func ParsePrivateKey(pemBytes []byte) (key *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

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
