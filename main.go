// Copyright (C) 2025 Avi Brender.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"mfgdat/certificate"
	"os"
	"path"
	"path/filepath"
	"slices"
	"text/tabwriter"
	"time"
)

const (
	// The root certificate used to sign the certificate presented by the ONT to the gateway.
	attServicesRootCA = `-----BEGIN CERTIFICATE-----
MIIDjTCCAnWgAwIBAgIQaZZlNVfAj8C+PAyFWjR9TTANBgkqhkiG9w0BAQUFADBL
MQswCQYDVQQGEwJVUzEZMBcGA1UEChMQQVRUIFNlcnZpY2VzIEluYzEhMB8GA1UE
AxMYQVRUIFNlcnZpY2VzIEluYyBSb290IENBMB4XDTExMDIyNDAwMDAwMFoXDTMx
MDIyMzIzNTk1OVowSzELMAkGA1UEBhMCVVMxGTAXBgNVBAoTEEFUVCBTZXJ2aWNl
cyBJbmMxITAfBgNVBAMTGEFUVCBTZXJ2aWNlcyBJbmMgUm9vdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAPecTeoY88yWw8n8tjxSuhNGYvTeS6/J
vCmG5GEUwmqOrPwQp+dyuDQ6U5kXZAI43XTvEWBhqRvGk858JmvQm0fw/mj4l4fN
KzcEUSAEyKMuYSqaNavPEFRUGMcWx+lHC1ZDgrehVhRCdvGmTkOm5FC0QU2NBXDL
Hl9XswadhBH7KN5n673qgVaziazRt4m009wsbU2IlGq3duqReLJRmurdo1bT6AhK
PPLCOm5c956IhVNsuKy1rclNHvqR8XQH1slzDoQ2+bBXNxZGMFgEquLaraZodsWV
/HF9/1LOojb0BDa0nhvSCQ6vHhW1YSkkM3rLKX3ySkxyGnek4w/rOwkCAwEAAaNt
MGswEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwJgYDVR0RBB8w
HaQbMBkxFzAVBgNVBAMTDk1QS0ktMjA0OC0xLTkyMB0GA1UdDgQWBBSXIJnCcypF
6+ACf0fae6t86x+vbjANBgkqhkiG9w0BAQUFAAOCAQEAq/zvYiIjZgYvpgRL4oUi
CaYqHWrWSYHG+k0zRGw1ysu4MxsaHY3JMQmF7E0OoBPsLuxfOvVxUCRrO0CFyBtJ
3s49FhLtRTrQGs/7DoL+tL80pIsgH7EX9a4koD/fjuCZe1dr9JsHqI0SUblfy5CX
s6BnhoXTJYAa47RhJwqMJ8jMRsUEKWPBDc13EGH6+w3Sw2CMvvWuriKSFicLlmLc
OrIPBwSwELYAd82Vm7HQO2HbHO/hp+VewqZiXWErWjWr+D0ScfNR82gwkaDPwZUZ
Tju8Z+QyAsLMtdBtFBoRtWs4kJLQWvXbILTpICxl8dYQFZ7Sv4dxdl2GdsNNtSSo
xw==
-----END CERTIFICATE-----`

	wpaSupplicantText = `eapol_version=1
ap_scan=0
fast_reauth=1
openssl_ciphers=DEFAULT@SECLEVEL=0
network={
        ca_cert="/full/path/to/%s"
        client_cert="/full/path/to/%s"
        eap=TLS
        eapol_flags=0
        identity="%s"
        key_mgmt=IEEE8021X
        phase1="allow_canned_success=1 allow_unsafe_renegotiation=1"
        private_key="/full/path/to/%s"
}
`
)

// writeTarGz writes a .tar.gz file to `w` containing a wpa_supplicant.conf file and related certificate and keys.
func writeTarGz(s *certificate.Bundle, w io.Writer, mtime time.Time) error {
	var buf bytes.Buffer // Used to temporarily store PEM-encoded data. Reset() must be called between uses.
	files := map[string][]byte{}

	serialNumber := s.ClientCertificate.Subject.SerialNumber
	macAddress := s.ClientCertificate.Subject.CommonName

	clientCertFilename := "client_cert_" + serialNumber + ".pem"
	caCertFilename := "ca_certs_" + serialNumber + ".pem"
	privateKeyFilename := "private_key_" + serialNumber + ".pem"
	wpaSupplicantFilename := "wpa_supplicant.conf"

	gzipWriter := gzip.NewWriter(w)
	// Set some header fields to static values so we generate deterministic output.
	gzipWriter.ModTime = mtime
	gzipWriter.Name = ""
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Write the client device certificate output file.
	fmt.Println("Found device certificate:")
	tabWriter := tabwriter.NewWriter(os.Stdout, 0, 8, 2, '\t', 0)
	fmt.Fprintf(tabWriter, "\tSerial Number:\t%s\n", serialNumber)
	fmt.Fprintf(tabWriter, "\tMAC Address:\t%s\n", macAddress)
	fmt.Fprintf(tabWriter, "\tIssuer:\t%s\n\n", s.ClientCertificate.Issuer.CommonName)
	tabWriter.Flush()

	buf.Reset()
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: s.ClientCertificate.Raw}); err != nil {
		return fmt.Errorf("could not PEM encode client certificate: %v", err)
	}
	files[clientCertFilename] = bytes.Clone(buf.Bytes())

	// Write the CA certificate output file.
	buf.Reset()
	for _, cert := range s.CACertificates {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Errorf("could not PEM encode CA certificate: %v", err)
		}
		fmt.Printf("Found chain certificate: %s\n", cert.Subject.CommonName)
	}
	buf.WriteString(attServicesRootCA + "\n")
	files[caCertFilename] = bytes.Clone(buf.Bytes())

	// Write the client device private key output file.
	buf.Reset()
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(s.ClientPrivateKey)
	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("could not PEM encode private device key: %v", err)
	}
	fmt.Printf("Found RSA private key\n\n")
	files[privateKeyFilename] = bytes.Clone(buf.Bytes())

	// Write the wpa_supplicant.conf output file.
	content := fmt.Sprintf(wpaSupplicantText, caCertFilename, clientCertFilename, macAddress, privateKeyFilename)
	files[wpaSupplicantFilename] = []byte(content)

	// Add all output files to the tar.Writer.
	//
	// Generating deterministic output requires that file names be sorted because iteration order on a map is undefined.
	for _, filename := range slices.Sorted(maps.Keys(files)) {
		content := files[filename]
		tarHeader := &tar.Header{
			Name:    filename,
			Size:    int64(len(content)),
			Mode:    0600,
			ModTime: mtime,
			Uid:     100,
			Gid:     100,
		}

		if err := tarWriter.WriteHeader(tarHeader); err != nil {
			return fmt.Errorf("could not write tar header for file %q: %v", filename, err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			return fmt.Errorf("could not write tar content for file %q: %v", filename, err)
		}
	}

	return nil
}

// Run reads the mfg.dat file at `inputFilePath` and writes the output .tar.gz file into `outputDir`.
// `mtime` is set as the modification time for the contents of the .tar.gz file. Passing a known inputFilePath and mtime
// to this function will generate a deterministic output that can be compared to a golden file.
func Run(inputFilePath string, outputDir string, mtime time.Time) error {
	fmt.Printf("Reading input file: %s\n\n", inputFilePath)
	mfgDatBytes, err := os.ReadFile(inputFilePath)
	if err != nil {
		return fmt.Errorf("could not read file %q: %v", inputFilePath, err)
	}

	var bundle *certificate.Bundle
	if bundle, err = certificate.ParseMfgDat(mfgDatBytes); err != nil {
		return fmt.Errorf("error parsing mfg.dat file: %v\n", err)
	}

	outputFileName := bundle.ClientCertificate.Subject.SerialNumber + ".tar.gz"
	outputFilePath := outputFileName
	if outputDir != "" {
		outputFilePath = path.Join(outputDir, outputFileName)
	}
	outputFile, err := os.OpenFile(outputFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("could not create output file (%q): %v", outputFileName, err)
	}
	defer outputFile.Close()

	outputFileAbsolutePath, err := filepath.Abs(outputFilePath)
	if err != nil {
		return fmt.Errorf("could not resolve absolute path for output file (%q): %v", outputFileName, err)
	}

	if err := writeTarGz(bundle, outputFile, mtime); err != nil {
		return fmt.Errorf("could not write .tar.gz output: %v", err)
	}

	fmt.Printf("Wrote output to %s\n\n", outputFileAbsolutePath)
	fmt.Println("IMPORTANT: The file paths in wpa_supplicant.conf must be changed.")

	return nil
}

func main() {
	fmt.Println("Copyright (C) 2025 Avi Brender.")
	fmt.Println("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>")
	fmt.Println()
	fmt.Println("This is free software; you are free to change and redistribute it.")
	fmt.Println("There is NO WARRANTY, to the extent permitted by law.")
	fmt.Println()

	if len(os.Args) == 1 {
		os.Args = append(os.Args, "mfg.dat")
	}

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <path/to/mfg.dat>\n", os.Args[0])
		os.Exit(1)
	}

	if err := Run(os.Args[1], "", time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
