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

var valid_first_byte = []byte{128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185}

type PublicKey = blst.P1Affine

func hasPrefix(key *PublicKey, prefix []byte) bool {
	keyData := key.Compress()
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
			fmt.Println("public key", hex.EncodeToString(pk.Compress()))
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

	validFirstByte := false
	for _, val := range valid_first_byte {
		if prefix[0] == val {
			validFirstByte = true
			break
		}
	}
	if !validFirstByte {
		fmt.Println("first byte should be one of the following")
		for _, val := range valid_first_byte {
			fmt.Printf("%x\n", val)
		}
		return
	}

	var count *uint64 = new(uint64)
	start := time.Now()

	triesNeeded := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(len(prefix))), nil)
	triesNeeded.Div(triesNeeded, big.NewInt(int64(255/len(valid_first_byte)))) // bias because first byte may have certain values
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
