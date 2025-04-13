package certificate

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
)

type modelT struct {
	name string // Name of the device model. This name will be returned to callers of this package.
	// Parameters used for AES decryption of the client private key.
	aesKey []byte
	aesIV  []byte
	// Some devices such as the BGW210-700 have unneeded bytes that must be stripped away before decoding.
	// A preprocessor function can be specified to manipulate raw data before decryption.
	preprocessor func([]byte) ([]byte, error)
}

// Credit to rss (@rssor) and d (@slush0_) of 8311 for this information.
var models = []modelT{
	{
		name:   "BGW210-700",
		aesKey: []byte{0x8C, 0x02, 0xE4, 0x9C, 0x55, 0xBA, 0xE5, 0x6C, 0x4B, 0xE5, 0x52, 0xB5, 0x0B, 0x41, 0xD6, 0x9F},
		aesIV:  []byte{0x2F, 0x79, 0xD4, 0x17, 0x3A, 0x15, 0x5E, 0x3B, 0xD0, 0x79, 0xDE, 0x4C, 0x81, 0x71, 0x9D, 0x3C},
		preprocessor: func(encrypted []byte) ([]byte, error) {
			if val := binary.BigEndian.Uint32(encrypted); val != 1 {
				return nil, fmt.Errorf("first word of the private key should be 1, found 0x%X", val)
			}
			// Skip the first 2 words, which are not part of the encrypted data.
			return encrypted[2*4:], nil
		},
	},
	{
		name:   "BGW320-500",
		aesKey: []byte{0x5C, 0x48, 0xCE, 0x30, 0x94, 0x48, 0x99, 0xFC, 0x79, 0x1A, 0x7C, 0xDE, 0x5A, 0x90, 0xA0, 0xE1},
		aesIV:  []byte{0x81, 0x89, 0x82, 0xFE, 0x6E, 0xC4, 0x8D, 0x35, 0x8C, 0xD2, 0xE3, 0x5B, 0xFB, 0x4C, 0x27, 0x4C},
	},
	{
		name:   "BGW320-505",
		aesKey: []byte{0xF5, 0x4E, 0x69, 0x81, 0x68, 0x6E, 0x97, 0x4B, 0x02, 0xE5, 0x70, 0x72, 0xDF, 0x53, 0x99, 0xDD},
		aesIV:  []byte{0x0A, 0xC0, 0xFB, 0x41, 0x02, 0x68, 0x9D, 0xA0, 0x18, 0x40, 0x8D, 0xF4, 0x8D, 0x80, 0xA6, 0x2B},
	},
	{
		name:   "BGW620-700",
		aesKey: []byte{0xA9, 0xA6, 0x21, 0xFC, 0xBF, 0x66, 0x3E, 0x04, 0x59, 0x9E, 0x0E, 0x2F, 0x96, 0xA3, 0xFD, 0xEB},
		aesIV:  []byte{0x83, 0x4C, 0x4C, 0x7D, 0x5D, 0x25, 0xC2, 0x19, 0xC8, 0x1F, 0x67, 0xA8, 0x86, 0xFE, 0x89, 0x8E},
	},
}

func (m modelT) decryptPKCS8PrivateKey(encrypted []byte) (*rsa.PrivateKey, error) {
	rawData := bytes.Clone(encrypted)

	// Run the preprocessor function, if one is defined.
	if m.preprocessor != nil {
		processed, err := m.preprocessor(encrypted)
		if err != nil {
			return nil, fmt.Errorf("preprocessor failed: %v", err)
		}
		rawData = processed
	}

	// Perform the AES decryption.
	decrypted, err := aesDecrypt(rawData, m.aesKey, m.aesIV)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}

	// Parse the DER-formatted PKCS8 private key.
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(decrypted)
	if err != nil {
		return nil, fmt.Errorf("error parsing PKCS8 private key: %v", err)
	}

	// A type assertion is needed because x509.ParsePKCS8PrivateKey returns an `any` type.
	privateKey, ok := privateKeyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	// Perform basic sanity checking on the private key.
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("error validating PKCS#8 private key: %v", err)
	}

	return privateKey, nil
}

// aesDecrypt uses the key and IV to decrypt the slice of bytes.
func aesDecrypt(encrypted []byte, key []byte, iv []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %v", err)
	}
	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("private key size (%d bytes) is not a multiple of the block size (%d)", len(encrypted), aes.BlockSize)
	}

	// Decrypt the bytes.
	decryptedBytes := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(aesBlock, iv).CryptBlocks(decryptedBytes, encrypted)

	return decryptedBytes, nil
}
