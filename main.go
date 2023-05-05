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

var algorithms = map[string]func() hash.Hash{
	"crc32": func() hash.Hash {
		return crc32.NewIEEE()
	},
	"md5":    md5.New,
	"sha1":   sha1.New,
	"sha224": sha256.New224,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

func main() {
	var text string
	var numParallel int

	flag.StringVar(&text, "s", "", "hash a specific string instead of files")
	flag.IntVar(&numParallel, "p", runtime.NumCPU(), "maximum parallel processing")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [FLAG]... ALGORITHM FILE...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [FLAG]... -s STRING ALGORITHM\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Println()

		fmt.Fprintf(os.Stderr, "Supported algorithms:\n")
		for k := range algorithms {
			fmt.Fprintf(os.Stderr, "  %s\n", k)
		}
		fmt.Println()

		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s sha256 /usr/bin/ls\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -s 'string to be hashed' md5\n", os.Args[0])
	}

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if text == "" && flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	newHash, ok := algorithms[flag.Arg(0)]
	if !ok {
		flag.Usage()
		os.Exit(1)
	}

	// if -s is passed, hash string passed from flag instead of file(s)
	if text != "" {
		h := newHash()
		_, _ = h.Write([]byte(text))
		res := h.Sum(nil)
		fmt.Printf("%s  '%s'\n", hex.EncodeToString(res), text)
		return
	}

	// channel for limiting concurrent processing
	sem := make(chan struct{}, numParallel)

	// index of the current file that will be printed the hash (or error message).
	// this number is atomically incremented until all files are printed in order.
	currFile := int32(0)

	// the names of the files that will be processed
	fnames := flag.Args()[1:]

	wg := sync.WaitGroup{}
	wg.Add(len(fnames))

	for i, fname := range fnames {
		i := int32(i)
		h := newHash()
		fname := fname
		sem <- struct{}{}

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

			<-sem
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
