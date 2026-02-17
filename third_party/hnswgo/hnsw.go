package hnswgo

// #cgo CXXFLAGS: -fPIC -pthread -Wall -std=c++11 -O2 -march=native -I.
// #cgo LDFLAGS: -pthread
// #cgo CFLAGS: -I./
// #include <stdlib.h>
// #include "hnsw_wrapper.h"
import "C"
import (
	"errors"
	"unsafe"
)

type SpaceType int

const (
	L2 SpaceType = iota
	IP
	Cosine
)

// HnswIndex wraps the C index type and provides a set of useful index manipulation methods.
type HnswIndex struct {
	index *C.HnswIndex
}

// SearchResult is the result returned by search method. Field Distance may be of
// euclidean distance or inner product distance, or cosine distance, depending on the chosen space type.
type SearchResult struct {
	Label    uint64
	Distance float32
}

// Create a new HnswIndex with  the specified dimension and other parameters. For details please see hnswlib documents.
// When allowReplaceDeleted is set, deleted elements can be replaced with new added ones.
func New(dim, M, efConstruction, randSeed int, maxElements uint64, spaceType SpaceType, allowReplaceDeleted bool) *HnswIndex {
	var allowReplace int = 0
	if allowReplaceDeleted {
		allowReplace = 1
	}

	var sType C.spaceType = C.l2
	switch spaceType {
	case L2:
		sType = C.l2
	case IP:
		sType = C.ip
	case Cosine:
		sType = C.cosine
	}

	cindex := C.newIndex(sType, C.int(dim), C.size_t(maxElements), C.int(M), C.int(efConstruction), C.int(randSeed), C.int(allowReplace))
	if cindex == nil {
		return nil
	}

	return &HnswIndex{
		index: cindex,
	}
}

// Loads data from existing HNSW index.
func Load(location string, spaceType SpaceType, dim int, maxElements uint64, allowReplaceDeleted bool) *HnswIndex {
	var allowReplace int = 0
	if allowReplaceDeleted {
		allowReplace = 1
	}

	var sType C.spaceType = C.l2
	switch spaceType {
	case L2:
		sType = C.l2
	case IP:
		sType = C.ip
	case Cosine:
		sType = C.cosine
	}

	cloc := C.CString(location)
	defer C.free(unsafe.Pointer(cloc))

	cindex := C.loadIndex(cloc, sType, C.int(dim), C.size_t(maxElements), C.int(allowReplace))
	if cindex == nil {
		return nil
	}

	return &HnswIndex{
		index: cindex,
	}
}

// Sets the query time accuracy/speed trade-off, defined by the ef parameter ( see doc ALGO_PARAMS.md of hnswlib).
// Note that the parameter is currently not saved along with the index, so you need to set it manually after loading.
func (idx *HnswIndex) SetEf(ef int) {
	if idx == nil || idx.index == nil {
		return
	}
	C.setEf(idx.index, C.size_t(ef))
}

// Returns index file size in bytes.
func (idx *HnswIndex) IndexFileSize() uint64 {
	sz := C.indexFileSize(idx.index)

	return uint64(sz)
}

// Save writes index data to disk.
func (idx *HnswIndex) Save(location string) {
	cloc := C.CString(location)
	defer C.free(unsafe.Pointer(cloc))

	C.saveIndex(idx.index, cloc)
}

// Adds points. Updates the point if it is already in the index.
// If replacement of deleted elements is enabled: replaces previously deleted point if any, updating it with new point.
func (idx *HnswIndex) AddPoints(vectors [][]float32, labels []uint64, concurrency int, replaceDeleted bool) error {
	var replace int = 0
	if replaceDeleted {
		replace = 1
	}

	if len(vectors) <= 0 || len(labels) <= 0 {
		return errors.New("invalid vector data")
	}

	if len(labels) != len(vectors) {
		return errors.New("unmatched vectors size and labels size")
	}

	if len(vectors[0]) != int(idx.index.dim) {
		return errors.New("unmatched dimensions of vector and index")
	}

	rows := len(vectors)
	flatVectors := flatten2DArray(vectors)

	//as a Go []float32 is layout-compatible with a C float[] so we can pass  Go slice directly to the C function as a pointer to its first element.
	errCode := C.addPoints(idx.index,
		(*C.float)(unsafe.Pointer(&flatVectors[0])),
		C.int(rows),
		(*C.size_t)(unsafe.Pointer(&labels[0])),
		C.int(concurrency),
		C.int(replace))

	if int(errCode) != 0 {
		return errors.New("add point failed, check logged error to see details")
	}

	return nil
}

// flatten the vectors to prevent the "cgo argument has Go pointer to unpinned Go pointer" issue.
func flatten2DArray(vectors [][]float32) []float32 {
	rows := len(vectors)
	dim := len(vectors[0])
	flatVectors := make([]float32, 0, rows*dim)

	for _, vector := range vectors {
		flatVectors = append(flatVectors, vector...)
	}

	return flatVectors
}

// SearchKNN do a batch query against the index using the provided vectors. concurrency set the threads to use for searching.
// For each of the queried vector, topK SearchResults will be returned if no error occured.
func (idx *HnswIndex) SearchKNN(vectors [][]float32, topK int, concurrency int) ([][]*SearchResult, error) {
	if len(vectors) <= 0 {
		return nil, errors.New("invalid vector data")
	}

	if len(vectors[0]) != int(idx.index.dim) {
		return nil, errors.New("unmatched dimensions of vector and index")
	}

	if uint64(topK) > uint64(C.getMaxElements(idx.index)) {
		return nil, errors.New("topK is larger than maxElements")
	}

	rows := len(vectors)
	flatVectors := flatten2DArray(vectors)
	cResult := C.searchKnn(idx.index,
		(*C.float)(unsafe.Pointer(&flatVectors[0])),
		C.int(rows),
		C.int(topK),
		C.int(concurrency),
	)
	if cResult == nil {
		return nil, errors.New("search knn failed")
	}

	defer C.freeResult(cResult)

	results := make([][]*SearchResult, rows) //the resulting slice
	for rowID := range results {
		rowTopk := make([]*SearchResult, topK)
		for j := 0; j < topK; j++ {
			r := SearchResult{}
			r.Label = *(*uint64)(unsafe.Add(unsafe.Pointer(cResult.label), (rowID*topK+j)*C.sizeof_ulong))
			r.Distance = *(*float32)(unsafe.Add(unsafe.Pointer(cResult.dist), (rowID*topK+j)*C.sizeof_float))
			rowTopk[j] = &r
		}
		results[rowID] = rowTopk
	}

	return results, nil

}

// Getting vector data by label.
func (idx *HnswIndex) GetDataByLabel(label uint64) []float32 {
	var vec []float32 = make([]float32, idx.index.dim)

	C.getDataByLabel(idx.index, C.size_t(label), (*C.float)(unsafe.Pointer(&vec)))
	return vec
}

// Get the setting of allowReplaceDeleted.
func (idx *HnswIndex) GetAllowReplaceDeleted() bool {
	return C.getAllowReplaceDeleted(idx.index) > 0
}

// Marks the element as deleted, so it will be omitted from search results.
func (idx *HnswIndex) MarkDeleted(label uint64) {
	C.markDeleted(idx.index, C.size_t(label))
}

// Unmarks the element as deleted, so it will be not be omitted from search results.
func (idx *HnswIndex) UnmarkDeleted(label uint64) {
	C.unmarkDeleted(idx.index, C.size_t(label))
}

// Resize changes the maximum capacity of the index.
func (idx *HnswIndex) ResizeIndex(newSize uint64) {
	C.resizeIndex(idx.index, C.size_t(newSize))
}

// Returns the current capacity of the index
func (idx *HnswIndex) GetMaxElements() uint64 {
	return uint64(C.getMaxElements(idx.index))
}

// Returns the current number of element stored in the index.
func (idx *HnswIndex) GetCurrentCount() uint64 {
	return uint64(C.getCurrentCount(idx.index))
}

// Free resources bound to the index. Should be called when index is destroyed on close.
func (idx *HnswIndex) Free() {
	C.freeHNSW(idx.index)
}
