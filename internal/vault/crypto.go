package vault

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const MaxFileSize = 16 << 20

func Encrypt(plain []byte, recipient age.Recipient) ([]byte, error) {
	var out bytes.Buffer
	armored := armor.NewWriter(&out)
	w, err := age.Encrypt(armored, recipient)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(plain); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	if err = armored.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func Decrypt(cipher []byte, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(cipher)), identity)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt: wrong key/password or invalid ciphertext")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("ciphertext authentication failed")
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("file exceeds 16 MiB limit")
	}
	return data, nil
}
