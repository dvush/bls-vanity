package main

import "testing"

func BenchmarkSearchForSeed(b *testing.B) {
	count := new(uint64)
	for i := 0; i < b.N; i++ {
		searchForSeed(count, 10000, []byte{1, 2, 3, 4, 5}, nil)
	}
}
