// Package certificate parses and exposes certificates and private keys from an mfg.dat file.
// Copyright (C) 2025 Avi Brender.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
package certificate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
)

const (
	certificateSectionOffset = -0x4000
	magic1                   = 0x0E0C0A08
	magic2                   = 0x02040607
)

// Parameters used for AES decryption of the client private key.
var aesKey = []byte{0x8C, 0x02, 0xE4, 0x9C, 0x55, 0xBA, 0xE5, 0x6C, 0x4B, 0xE5, 0x52, 0xB5, 0x0B, 0x41, 0xD6, 0x9F}
var aesIV = []byte{0x2F, 0x79, 0xD4, 0x17, 0x3A, 0x15, 0x5E, 0x3B, 0xD0, 0x79, 0xDE, 0x4C, 0x81, 0x71, 0x9D, 0x3C}

// The 3rd word of each entry contains an integer representing the type of data stored in that entry. These are the
// known values for this data.
type entryT uint32

const (
	entryTypeClientCert         entryT = 2
	entryTypeCACert             entryT = 3
	entryTypeClientKeyEncrypted entryT = 4
)

// Bundle contains certificate & key entries from the certificate section of mfg.dat.
type Bundle struct {
	ClientCertificate *x509.Certificate
	ClientPrivateKey  *rsa.PrivateKey
	CACertificates    []*x509.Certificate
}

func ParseMfgDat(mfgDat []byte) (*Bundle, error) {
	bundle := new(Bundle)

	if err := bundle.parse(mfgDat[len(mfgDat)+certificateSectionOffset:]); err != nil {
		return nil, fmt.Errorf("error parsing mfg.dat file at offset %Xh: %v", certificateSectionOffset, err)
	}

	return bundle, nil
}

func (b *Bundle) parse(certificateSection []byte) error {
	byteReadIndex := 0

	// readWord function will panic when called too many times. There is no bounds checking of the slice indexes. This
	// is to simplify the function signature such that error checking is not required. The scope of this function is
	// limited to parse(), and it is only called a few times, therefore this trade-off is reasonable.
	readWord := func() uint32 {
		defer func() { byteReadIndex = byteReadIndex + 4 }()
		return binary.BigEndian.Uint32(certificateSection[byteReadIndex : byteReadIndex+4])
	}

	// Verify the magic values.
	if word1, word2 := readWord(), readWord(); word1 != magic1 || word2 != magic2 {
		return fmt.Errorf("magic bytes did not match. Expected 0x%x and 0x%x, got 0x%x and 0x%x", magic1, magic2, word1, word2)
	}

	// Word 3 contains the total length (in bytes) of the certificate section.
	// The value includes the first 2 (magic) words and the length field itself.
	certificateSectionLen := int(readWord())
	if certificateSectionLen > len(certificateSection) {
		return fmt.Errorf("length (%d) out of range (certificate section is %d bytes)", certificateSectionLen, len(certificateSection))
	}

	// Word 4 contains the number of items (read: certificates & keys) in the certificate section.
	entryCount := int(readWord())
	if entryCount > 20 { // 20 is an arbitrary number. A real-world random BGW210 has 4 entries.
		return fmt.Errorf("got suspiciously large certificate count: %d", entryCount)
	}

	// Word 5 is not used.
	_ = readWord()

	sizeOfEntryInBytes := 4 * 4 // Entries are composed of 4x 4-byte words.
	rawData := certificateSection[(byteReadIndex + entryCount*(sizeOfEntryInBytes)):]

	// Parse the entries.
	entries := map[entryT][][]byte{}
	for i := 1; i <= int(entryCount); i++ {
		entryOffset := int(readWord())
		entryLength := int(readWord())
		entryType := entryT(readWord())
		_ = readWord() // The 4th word in the entry is not currently used.

		if (entryOffset + entryLength) > len(rawData) {
			return fmt.Errorf("entry %d (offset=%d, length=%d) exceeds the length of the raw data (%d)", i, entryOffset, entryLength, len(rawData))
		}

		entries[entryType] = append(entries[entryType], rawData[entryOffset:entryOffset+entryLength])
	}

	return b.processEntries(entries)
}

func (b *Bundle) processEntries(entries map[entryT][][]byte) error {
	var err error

	// Process the client device certificate.
	if count := len(entries[entryTypeClientCert]); count != 1 {
		return fmt.Errorf("expected exactly 1 client certificate, got %d", count)
	}
	b.ClientCertificate, err = x509.ParseCertificate(entries[entryTypeClientCert][0])
	if err != nil {
		return fmt.Errorf("could not parse client certificate: %v", err)
	}

	// Process the CA certificate.
	for _, entry := range entries[entryTypeCACert] {
		certs, err := x509.ParseCertificates(entry)
		if err != nil {
			return fmt.Errorf("could not parse CA certificate: %v", err)
		}
		b.CACertificates = append(b.CACertificates, certs...)
	}

	// Process the device private key.
	if count := len(entries[entryTypeClientKeyEncrypted]); count != 1 {
		return fmt.Errorf("expected exactly 1 private key, got %d", count)
	}
	privateKeyRawData := entries[entryTypeClientKeyEncrypted][0]
	if val := binary.BigEndian.Uint32(privateKeyRawData[0 : 3*4]); val != 1 {
		return fmt.Errorf("first word of the private key should be 1, found 0x%X", val)
	}

	// Strip off the first 2 words. They aren't part of the encrypted private key.
	privateKeyRawData = privateKeyRawData[2*4:]

	// Decrypt the private key bytes.
	decryptedBytes, err := decryptPrivateKey(privateKeyRawData)
	if err != nil {
		return fmt.Errorf("could not decrypt client key: %v", err)
	}

	// Parse the DER-formatted PKCS8 private key.
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(decryptedBytes)
	if err != nil {
		return fmt.Errorf("could not parse private PKCS8 key: %v", err)
	}

	// A type assertion is needed because x509.ParsePKCS8PrivateKey returns an `any` type.
	privateKey, ok := privateKeyAny.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key is not an RSA key")
	}

	if err := privateKey.Validate(); err != nil {
		return fmt.Errorf("private key validation failed: %v", err)
	}

	b.ClientPrivateKey = privateKey

	if err := b.validateKeyPair(); err != nil {
		return fmt.Errorf("public/private key pair validation failed; %v", err)
	}

	return nil
}

// validateKeyPair verifies that the public and private keys for the device are a matching pair.
func (b *Bundle) validateKeyPair() error {
	publicKey, ok := b.ClientCertificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("device certificate's public key is not an RSA public key")
	}

	if !publicKey.Equal(b.ClientPrivateKey.Public()) {
		return fmt.Errorf("public key does not match client private key")
	}

	return nil
}

// decryptPrivateKey decrypts the AES-128 encrypted device private key.
func decryptPrivateKey(encrypted []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %v", err)
	}
	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("private key size (%d bytes) is not a multiple of the block size (%d)", len(encrypted), aes.BlockSize)
	}

	// Decrypt the bytes.
	decryptedBytes := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(aesBlock, aesIV).CryptBlocks(decryptedBytes, encrypted)

	return decryptedBytes, nil
}
