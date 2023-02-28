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
	"sync"
	"sync/atomic"
	"time"
)

var sFlag string
var parallelFlag int

func init() {
	flag.StringVar(&sFlag, "s", "", "hash a specific string instead of files")
	flag.IntVar(&parallelFlag, "p", runtime.NumCPU(), "disable hash parallel computing")

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
	default:
		flag.Usage()
		os.Exit(1)
	}

	// if -s is passed, hash string passed from flag instead of file(s)
	if sFlag != "" {
		h := newHash()
		_, _ = h.Write([]byte(sFlag))
		res := h.Sum(nil)
		fmt.Printf("%s  %s\n", hex.EncodeToString(res), sFlag)
		return
	}

	// channel for limiting concurrent processing for up `parallelFlag`
	chLimit := make(chan struct{}, parallelFlag)

	// index of the current file that will be printed the hash (or error message).
	// this number is atomically incremented until all files were printed in order.
	currFile := int32(0)

	// the names of the files that will be processed
	fnames := flag.Args()[1:]

	wg := sync.WaitGroup{}
	wg.Add(len(fnames))

	for i, fname := range fnames {
		i := int32(i)
		h := newHash()
		fname := fname
		chLimit <- struct{}{}

		go func() {
			defer wg.Done()
			defer atomic.StoreInt32(&currFile, i+1)

			s, err := computeFileHash(h, fname)

			// although results are computed in parallel, they are shown in
			// the original order they are passed through args.
			// this loop waits until it is time to show this result
			for {
				c := atomic.LoadInt32(&currFile)
				if c == i {
					break
				}
				time.Sleep(time.Millisecond)
			}

			// If hashing failed, show error on stderr, otherwise print hash & filenmae
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
			} else {
				fmt.Println(s + "  " + fname)
			}

			<-chLimit
		}()
	}

	wg.Wait()
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
