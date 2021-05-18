package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/gballet/go-verkle"
	"github.com/protolambda/go-kzg"
	"github.com/protolambda/go-kzg/bls"
)

// GenerateTestingSetupWithLagrange creates a setup of n values from the given secret,
// along with the  **for testing purposes only**
func GenerateTestingSetupWithLagrange(secret string, n uint64, fftCfg *kzg.FFTSettings) ([]bls.G1Point, []bls.G2Point, []bls.G1Point, error) {
	var s bls.Fr
	bls.SetFr(&s, secret)

	var sPow bls.Fr
	bls.CopyFr(&sPow, &bls.ONE)

	s1Out := make([]bls.G1Point, n, n)
	s2Out := make([]bls.G2Point, n, n)
	for i := uint64(0); i < n; i++ {
		bls.MulG1(&s1Out[i], &bls.GenG1, &sPow)
		bls.MulG2(&s2Out[i], &bls.GenG2, &sPow)
		var tmp bls.Fr
		bls.CopyFr(&tmp, &sPow)
		bls.MulModFr(&sPow, &tmp, &s)
	}

	s1Lagrange, err := fftCfg.FFTG1(s1Out, true)

	return s1Out, s2Out, s1Lagrange, err
}

func main() {
	//benchmarkInsertInExisting(10)
	//benchmarkInsertInExisting(8)
	benchmarkMultiExpThreshold(10)
	benchmarkMultiExpThreshold(8)
}

func benchmarkInsertInExisting(width uint8) {
	rand.Seed(time.Now().UnixNano())

	// Number of existing leaves in tree
	n := 1000000
	// Leaves to be inserted afterwards
	toInsert := 10000
	total := n + toInsert

	keys := make([][]byte, n)
	toInsertKeys := make([][]byte, toInsert)
	value := []byte("value")

	for i := 0; i < 4; i++ {
		// Generate set of keys once
		for i := 0; i < total; i++ {
			key := make([]byte, 32)
			rand.Read(key)
			if i < n {
				keys[i] = key
			} else {
				toInsertKeys[i-n] = key
			}
		}
		fmt.Printf("Generated key set %d\n", i)

		// Create tree from same keys multiple times
		for i := 0; i < 5; i++ {
			root := verkle.New(int(width))
			for _, k := range keys {
				if err := root.Insert(k, value); err != nil {
					panic(err)
				}
			}
			root.ComputeCommitment()

			// Now insert the 10k leaves and measure time
			start := time.Now()
			for _, k := range toInsertKeys {
				if err := root.Insert(k, value); err != nil {
					panic(err)
				}
			}
			root.ComputeCommitment()
			elapsed := time.Since(start)
			fmt.Printf("Took %v to insert and commit %d leaves\n", elapsed, toInsert)
		}
	}
}

func benchmarkMultiExpThreshold(width int) {
	cfg := verkle.GetTreeConfig(width)

	n := 1 << width
	poly := make([]bls.Fr, n)

	// Try linear combination with different number of
	// non-zero values. Starting from 1 non-zero, up to 1024.
	for i := 0; i < n; i++ {
		for j := 0; j <= i; j++ {
			v := make([]byte, 2)
			binary.BigEndian.PutUint16(v, uint16(j))
			verkle.HashToFr(&poly[j], sha256.Sum256(v), cfg.Modulus())
		}
		// Run LinCombG1 and GBomb a 100 times
		// to get a more reliable runtime estimate
		lincomb := int64(0)
		gbomb := int64(0)
		for k := 0; k < 100; k++ {
			lincombStart := time.Now()
			bls.LinCombG1(cfg.LG1(), poly[:])
			lincomb += time.Since(lincombStart).Nanoseconds()

			gbombStart := time.Now()
			verkle.LinCombGBomb(cfg.LG1(), poly[:])
			gbomb += time.Since(gbombStart).Nanoseconds()
		}
		lincomb /= 100
		gbomb /= 100

		if gbomb > lincomb {
			fmt.Printf("Cutoff at %d. LinComb %vns, GBomb %vns\n", i, lincomb, gbomb)
			break
		}
	}
}
