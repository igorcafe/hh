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
	"runtime"
	"sync/atomic"
)

var sFlag string
var noParallelFlag bool

func init() {
	flag.StringVar(&sFlag, "s", "", "hash a specific string instead of files")
	flag.BoolVar(&noParallelFlag, "nop", false, "disable hash parallel computing")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [FLAG]... ALGORITHM FILE...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [FLAG]... -s STRING ALGORITHM\n", os.Args[0])
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

	var newHash func() hash.Hash

	switch flag.Args()[0] {
	case "md5":
		newHash = md5.New
	case "sha1":
		newHash = sha1.New
	case "sha224":
		newHash = sha256.New224
	case "sha256":
		newHash = sha256.New
	case "sha384":
		newHash = sha512.New384
	case "sha512":
		newHash = sha512.New
	case "crc32":
		newHash = func() hash.Hash {
			return crc32.NewIEEE()
		}
	}

	if sFlag != "" {
		h := newHash()
		_, _ = h.Write([]byte(sFlag))
		res := h.Sum(nil)
		fmt.Printf("%s  %s\n", hex.EncodeToString(res), sFlag)
		return
	}

	maxGoroutines := runtime.NumCPU()
	if noParallelFlag {
		maxGoroutines = 1
	}

	chLimit := make(chan struct{}, maxGoroutines)
	curr := int32(0)
	nfiles := flag.NArg() - 1
	finished := make(chan struct{})

	for i, fname := range flag.Args()[1:] {
		i := int32(i)
		h := newHash()
		fname := fname
		chLimit <- struct{}{}

		go func() {
			msg := ""
			ok := true
			s, err := computeFileHash(h, fname)

			if err != nil {
				ok = false
				msg = fmt.Sprintln(err.Error())
			} else {
				msg = fmt.Sprintf("%s  %s\n", s, fname)
			}

			for {
				c := atomic.LoadInt32(&curr)
				if c == i {
					break
				}
			}

			if ok {
				fmt.Print(msg)
			} else {
				fmt.Fprint(os.Stderr, msg)
			}

			if i == int32(nfiles)-1 {
				close(finished)
			} else {
				atomic.StoreInt32(&curr, i+1)
			}

			<-chLimit
		}()
	}

	<-finished
}

func computeFileHash(h hash.Hash, fname string) (string, error) {
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
