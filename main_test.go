// Copyright (C) 2025 Avi Brender.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
package main_test

import (
	"bytes"
	"decoder"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	mtime := time.UnixMilli(0)

	tests := []struct {
		testName   string
		inputFile  string
		goldenFile string
	}{
		{
			testName:   "bgw210-700",
			inputFile:  "testdata/bgw210-700/mfg.dat", // Fake file created using make-fake-mfg-dat-bgw210-700.sh
			goldenFile: "testdata/bgw210-700/123ABC-P67AB2DR253311.tar.gz",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			tempDir := t.TempDir() // This directory is automatically removed when the test completes.
			if err := main.Run(test.inputFile, tempDir, mtime); err != nil {
				t.Fatalf("run() failed: %v", err)
			}

			want := mustReadFile(t, test.goldenFile)

			filename := path.Base(test.goldenFile)
			gotFile := filepath.Join(tempDir, filename)
			got := mustReadFile(t, gotFile)

			if !bytes.Equal(got, want) {
				t.Fatalf("contents of golden file (%q) and actual file (%q) are not equal", test.goldenFile, gotFile)
			}

		})
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read file %q: %v", path, err)
	}

	return contents
}
