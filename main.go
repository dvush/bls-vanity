package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	blst "github.com/supranational/blst/bindings/go"
	"math/big"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type PublicKey = blst.P1Affine

func hasPrefix(key *PublicKey, prefix []byte) bool {
	keyData := key.Serialize()
	return bytes.Compare(keyData[:len(prefix)], prefix) == 0
}

func searchForSeed(count *uint64, maxTries int, prefix []byte, wg *sync.WaitGroup) {
	var seed [32]byte

	for i := 0; maxTries == 0 || i < maxTries; i++ {
		_, err := rand.Read(seed[:])
		if err != nil {
			panic(err)
		}

		sk := blst.KeyGen(seed[:])
		pk := new(PublicKey).From(sk)

		hasPrefix(pk, prefix)

		if hasPrefix(pk, prefix) {
			fmt.Println("secret key", hex.EncodeToString(sk.Serialize()))
			fmt.Println("public key", hex.EncodeToString(pk.Serialize()))
			break
		}

		atomic.AddUint64(count, 1)
	}

	if wg != nil {
		wg.Done()
	}
}

func usage() {
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage\n%s: [options] <prefix>\n", os.Args[0])
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), "<prefix> - hex of prefix (e.g. 01dead01)\n")
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	cpu := flag.Int("cpu", 0, "num cpu to use, 0 - NumCpu Will be used")
	flag.Parse()
	if *cpu == 0 {
		*cpu = runtime.NumCPU()
	}
	if flag.NArg() != 1 {
		usage()
		return
	}
	prefixStr := flag.Arg(0)

	prefix, err := hex.DecodeString(prefixStr)
	if err != nil {
		panic(err)
	}
	if prefix[0] > 26 {
		panic("first byte should be in 0-26 range")
	}

	var count *uint64 = new(uint64)
	start := time.Now()

	triesNeeded := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(len(prefix))), nil)
	triesNeeded.Div(triesNeeded, big.NewInt(9)) // bias because first byte may be only 0-26
	go func() {
		for {
			time.Sleep(time.Second * 5)
			perSec := atomic.LoadUint64(count) / uint64(time.Since(start).Seconds())

			secs := new(big.Int).Div(triesNeeded, big.NewInt(int64(perSec)))

			expectedWait := time.Second * time.Duration(secs.Uint64())
			fmt.Println("tries per sec:", perSec, "expected wait time:", expectedWait, "time spent:", time.Since(start).Truncate(time.Second))
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < *cpu; i++ {
		wg.Add(1)
		go searchForSeed(count, 0, prefix, &wg)
	}

	wg.Wait()
}
