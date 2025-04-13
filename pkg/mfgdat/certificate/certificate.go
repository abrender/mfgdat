// Package certificate parses and exposes certificates and private keys from BGW gateways.
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
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"
)

const (
	// The magic bytes are used to identify the start of the certificate header in an mfg.dat/calibration_01.bin file.
	// (https://en.wikipedia.org/wiki/List_of_file_signatures).
	magic1 = 0x0E0C0A08
	magic2 = 0x02040607
)

type header struct {
	Magic1     uint32
	Magic2     uint32
	Len        uint32 // Length of the certificate section in bytes. This includes the header, entries and raw data.
	NumEntries uint32
	Unknown    uint32
}

type entry struct {
	// Starting address for the entry's raw data. The offset is in *bytes* relative to the start of the raw data.
	Offset uint32
	Length uint32 // Length of the entry in *bytes*.
	Type   entryT
	Flags  uint32 // 1 = Encrypted. Currently unused because this is only set when Type=4.
}

// The 3rd word of each entry contains an integer representing the type of data stored in that entry. These are the
// known values for this data.
type entryT uint32

const (
	entryTypeClientCert               entryT = 2
	entryTypeCACert                   entryT = 3
	entryTypeEncryptedPKCS8PrivateKey entryT = 4
)

// Bundle contains certificate & key entries from the certificate section of mfg.dat.
type Bundle struct {
	Model             string
	ClientCertificate *x509.Certificate
	ClientPrivateKey  *rsa.PrivateKey
	CACertificates    []*x509.Certificate
}

// ParseFile reads the input file bytes and returns a Bundle containing the client device certificate & key and the CA
// certificates.
func ParseFile(file []byte) (*Bundle, error) {
	bundle := new(Bundle)
	if err := bundle.parseCertificatesAndKey(file); err != nil {
		return nil, fmt.Errorf("error parsing the certificates and key: %v", err)
	}

	return bundle, nil
}

func (b *Bundle) parseCertificatesAndKey(file []byte) error {
	entries, err := parseEntries(file)
	if err != nil {
		return fmt.Errorf("error parsing entries: %v", err)
	}

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
	if count := len(entries[entryTypeEncryptedPKCS8PrivateKey]); count != 1 {
		return fmt.Errorf("expected exactly 1 private key, got %d", count)
	}

	privateKeyRawData := entries[entryTypeEncryptedPKCS8PrivateKey][0]
	privateKey, model, err := decryptPKCS8PrivateKey(privateKeyRawData)
	if err != nil {
		return fmt.Errorf("could not decrypt private key: %v", err)
	}

	if err := privateKey.Validate(); err != nil {
		return fmt.Errorf("private key validation failed: %v", err)
	}

	b.Model = model.name
	b.ClientPrivateKey = privateKey

	return b.validateKeyPair()
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

type entriesTable map[entryT][][]byte

// parseEntries reads and returns the parsed entries from the input file bytes.
func parseEntries(file []byte) (entriesTable, error) {
	var header header
	entries := make(entriesTable)

	header, data, err := findCertificateSection(file)
	if err != nil {
		return nil, fmt.Errorf("error finding certificate section in file: %v", err)
	}

	// Basic sanity checks.
	if totalLen := int(unsafe.Sizeof(header)) + len(data); int(header.Len) > totalLen {
		return nil, fmt.Errorf("header size (%d bytes) exceeds the data length (%d bytes)", header.Len, totalLen)
	}
	if header.Len > (10 * (1024 * 1024)) {
		return nil, fmt.Errorf("header size (%d bytes) is suspiciously large", header.Len)
	}
	if header.NumEntries > 10 {
		return nil, fmt.Errorf("found suspiciously large number of entries: %d", header.NumEntries)
	}

	// note that use of `unsafe.Sizeof` is ... unsafe. Go will pad and align structs so we have to be careful about
	// the order and type of fields we put in the `header` and `entry` structs.
	// https://go101.org/article/memory-layout.html

	sizeOfEntries := int64(header.NumEntries * uint32(unsafe.Sizeof(entry{})))
	entriesReader := io.LimitReader(bytes.NewReader(data), sizeOfEntries)

	sizeOfRawData := int64(int64(header.Len) - int64(sizeOfEntries) - int64(unsafe.Sizeof(header)))
	rawDataReader := io.NewSectionReader(bytes.NewReader(data), sizeOfEntries, sizeOfRawData)

	for i := 1; i <= int(header.NumEntries); i++ {
		var entry entry
		if err := binary.Read(entriesReader, binary.BigEndian, &entry); err != nil {
			return nil, fmt.Errorf("error reading entry %d: %v", i, err)
		}

		if entry.Length > (1024 * 1024) {
			return nil, fmt.Errorf("size of entry %d (%d bytes) is suspiciously large", i, entry.Length)
		}

		rawData := make([]byte, entry.Length)
		if _, err := rawDataReader.ReadAt(rawData, int64(entry.Offset)); err != nil {
			return nil, fmt.Errorf("error reading entry %d: %v", i, err)
		}

		entries[entry.Type] = append(entries[entry.Type], rawData)
	}
	return entries, nil
}

// findCertificateSection checks for the certificate section header at well-known offsets and returns the header and the
// bytes *after* the header (including the entries and raw data).
func findCertificateSection(file []byte) (header, []byte, error) {
	reader := bytes.NewReader(file)

	// The certificate section may be located at different parts of the file, so we search through some well-known
	// offsets and attempt to locate the certificate section.
	seeks := []struct {
		offset int64
		whence int
	}{
		{0, io.SeekStart},     // calibration_01.bin files start at offset 0 (the beginning of the file).
		{-0x4000, io.SeekEnd}, // mfg.dat files start at -0x4000.
	}

	for _, seek := range seeks {
		// Note: Errors are ignored within the loop because we always want to continue and try the next offset.
		if _, err := reader.Seek(seek.offset, seek.whence); err != nil {
			continue
		}
		var header header
		if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
			continue
		}
		if header.Magic1 != magic1 || header.Magic2 != magic2 {
			continue
		}
		data, err := io.ReadAll(reader)
		return header, data, err
	}

	return header{}, nil, fmt.Errorf("no certificate section found at any known offset")
}

// decryptPKCS8PrivateKey decrypts the raw bytes and returns an RSA private key.
func decryptPKCS8PrivateKey(encrypted []byte) (*rsa.PrivateKey, modelT, error) {
	for _, model := range models {
		privateKey, err := model.decryptPKCS8PrivateKey(encrypted)
		if err == nil {
			return privateKey, model, nil
		}
		// We proceed on errors because we want to check all the models before returning an error.
	}
	return nil, modelT{}, fmt.Errorf("could not decrypt encrypted data: no compatible model found")
}
