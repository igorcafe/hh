package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <algorithm> <file>\n", os.Args[0])
		os.Exit(1)
	}

	var h hash.Hash

	switch os.Args[1] {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha224":
		h = sha256.New224()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	case "crc32":
		h = crc32.NewIEEE()
	}

	fnames := os.Args[2:]

	for _, fname := range fnames {
		s, err := computeFileHash(h, fname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to compute hash for file %s: %s\n", fname, err.Error())
			continue
		}

		fmt.Printf("%s  %s\n", s, fname)
	}
}

func computeFileHash(h hash.Hash, fname string) (string, error) {
	defer h.Reset()
	f, err := os.Open(fname)
	if err != nil {
		return "", err
	}

	defer f.Close()

	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}

	sum := h.Sum(nil)
	hx := hex.EncodeToString(sum)
	return hx, nil
}
