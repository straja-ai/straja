package hnswgo

import (
	"errors"
	"math"
	"math/rand"
	"os"
	"testing"
)

const testVectorDB = "./test.db"
const (
	dim            = 400
	M              = 20
	efConstruction = 10

	batchSize = 100
)

func newTestIndex(batch int, allowRepaceDeleted bool) *HnswIndex {
	maxElements := batch * batchSize

	index := New(dim, M, efConstruction, 55, uint64(maxElements), Cosine, allowRepaceDeleted)

	for i := 0; i < batch; i++ {
		points, labels := randomPoints(dim, i*batchSize, batchSize)
		index.AddPoints(points, labels, 1, false)
	}

	return index
}

func TestNewIndex(t *testing.T) {
	var maxElements uint64 = batchSize * 1

	idx := newTestIndex(1, true)
	defer idx.Free()

	if idx.GetMaxElements() != maxElements {
		t.Fail()
	}

	if idx.GetAllowReplaceDeleted() != true {
		t.Fail()
	}

	if idx.GetCurrentCount() != maxElements {
		t.Fail()
	}

}

func TestLoadAndSaveIndex(t *testing.T) {
	var maxElements uint64 = batchSize * 1

	// setup
	idx := newTestIndex(1, true)
	idx.Save(testVectorDB)
	idx.Free()

	index := Load(testVectorDB, Cosine, dim, uint64(maxElements), true)
	index.SetEf(efConstruction)
	defer index.Free()

	index.Save(testVectorDB)
	t.Cleanup(func() {
		deleteDB()
	})
}

func TestResizeIndex(t *testing.T) {
	var maxElements uint64 = batchSize * 1

	idx := newTestIndex(1, false)
	defer idx.Free()

	if idx.GetMaxElements() != maxElements {
		t.Fail()
	}

	if idx.GetCurrentCount() != maxElements {
		t.Fail()
	}

	if idx.GetAllowReplaceDeleted() != false {
		t.Fail()
	}

	points, labels := randomPoints(dim, 1*batchSize, batchSize)
	err := idx.AddPoints(points, labels, 1, false)
	if err == nil {
		t.Log(err)
		t.FailNow()
	}

	idx.ResizeIndex(maxElements * 2)
	if idx.GetMaxElements() != maxElements*2 {
		t.Fail()
	}

	if idx.GetCurrentCount() != maxElements {
		t.Fail()
	}

	err = idx.AddPoints(points, labels, 1, false)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestReplacePoint(t *testing.T) {
	allowRepaceDeleted := true
	maxElements := 100
	index := New(dim, M, efConstruction, 505, uint64(maxElements), Cosine, allowRepaceDeleted)
	defer index.Free()

	if !index.GetAllowReplaceDeleted() {
		t.Fail()
	}

	points, labels := randomPoints(dim, 0, maxElements)
	index.AddPoints(points, labels, 1, false)

	index.MarkDeleted(labels[len(labels)-1])

	err := index.AddPoints([][]float32{randomPoint(dim)}, []uint64{math.MaxUint64-1}, 1, false)
	if err == nil {
		t.Fail()
	}

	err = index.AddPoints([][]float32{randomPoint(dim)}, []uint64{math.MaxUint64-1}, 1, true)
	if err != nil {
		t.Fail()
	}

}

func TestVectorSearch(t *testing.T) {
	dim := 400
	batchSize := 100
	maxElements := batchSize * 10000

	index := Load("./example.data", Cosine, dim, uint64(maxElements), true)
	index.SetEf(efConstruction)
	defer index.Free()

	query := genQuery(dim, 10)
	topK := 5

	result, err := index.SearchKNN(query, topK, 1)
	if err != nil {
		t.Error(err)
		t.Fail()
		return
	}

	if len(result) != len(query) {
		t.Fail()
	}

	for _, rv := range result {
		if len(rv) != topK {
			t.Fail()
			break
		}
	}

}

func TestGetVectorData(t *testing.T) {

}

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

	return points, labels
}

func genQuery(dim int, size int) [][]float32 {
	points := make([][]float32, size)

	for i := 0; i < size; i++ {
		v := make([]float32, dim)
		for i := range v {
			v[i] = rand.Float32()
		}
		points[i] = v
	}

	return points
}

func pathExists(path string) bool {
	stat, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}

	if err == nil || stat != nil {
		return true
	}

	return false
}

func deleteDB() error {
	if pathExists(testVectorDB) {
		return os.Remove(testVectorDB)
	}

	return nil
}

func randomPoint(dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rand.Float32()
	}
	return v
}
