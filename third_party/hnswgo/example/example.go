package main

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"time"

	"github.com/oligo/hnswgo"
)

func main() {
	dim := 400
	M := 20
	efConstruction := 10

	batchSize := 1000
	maxElements := 100000

	var index *hnswgo.HnswIndex
	if PathExists("./example.data") {
		index = hnswgo.Load("./example.data", hnswgo.Cosine, dim, uint64(maxElements), true)
		index.SetEf(efConstruction)
		defer index.Free()

	} else {
		start := time.Now()
		index = hnswgo.New(dim, M, efConstruction, 432, uint64(maxElements), hnswgo.Cosine, true)
		defer index.Free()

		for i := 0; i < 100; i++ {
			points, labels := randomPoints(dim, i*batchSize, batchSize)
			err := index.AddPoints(points, labels, 4, false)
			if err != nil {
				panic(err)
			}
		}
		defer index.Save("./example.data")
		fmt.Printf("Time elapsed: %f, max label: %d\n", time.Since(start).Seconds(), maxLabel)

	}

	query := [][]float32{randomPoint(dim), randomPoint(dim)}
	result, err := index.SearchKNN(query, 5, 1)
	if err != nil {
		panic(err)
	}

	for i, row := range result {
		for kth, rv := range row {
			fmt.Printf("#%d: topK-[%d] label: %d, distance: %f\n", i, kth, rv.Label, rv.Distance)
		}
	}

}

func randomPoint(dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rand.Float32()
	}
	return v
}

var maxLabel = uint64(0)

func randomPoints(dim int, startLabel int, batchSize int) ([][]float32, []uint64) {
	points := make([][]float32, batchSize)
	labels := make([]uint64, 0)

	for i := 0; i < batchSize; i++ {
		v := make([]float32, dim)
		for i := range v {
			v[i] = rand.Float32()
		}
		points[i] = v
		labels = append(labels, uint64(startLabel+i))
	}

	maxLabel = max(maxLabel, slices.Max(labels))
	return points, labels
}

func PathExists(path string) bool {
	stat, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}

	if err == nil || stat != nil {
		return true
	}

	return false
}
