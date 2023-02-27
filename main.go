package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
)

var sFlag string

func init() {
	flag.StringVar(&sFlag, "s", "", "hash a specific string instead of files")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s ALGORITHM FILE...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -s STRING ALGORITHM\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println()

		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s sha256 /usr/bin/ls\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -s 'string to be hashed' md5\n", os.Args[0])
	}

	flag.Parse()
}

func main() {
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if sFlag == "" && flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	var h hash.Hash

	switch flag.Args()[0] {
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

	if sFlag != "" {
		_, _ = h.Write([]byte(sFlag))
		res := h.Sum(nil)
		fmt.Printf("%s  %s\n", hex.EncodeToString(res), sFlag)
		return
	}

	for _, fname := range flag.Args()[1:] {
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
