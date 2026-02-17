// hnsw_wrapper.h
#ifdef __cplusplus
extern "C"
{
#endif

    typedef void *HNSW;
    typedef void *HnswSpace;
    typedef enum {
        l2, ip, cosine
    } spaceType;

    // The index wrapper with some needed properties if initialized index.
    typedef struct
    {
        HNSW hnsw;
        HnswSpace space;
        spaceType space_type;
        int dim;
        int normalize;
    } HnswIndex;

    //typedef bool (*filter_func)(int label);

    // SearchResult holds the multi-vector search result. label and dist are flatted 2d vectors.
    typedef struct
    {
        size_t *label;
        float *dist;
    } SearchResult;

    HnswIndex *newIndex(spaceType space_type, const int dim, size_t max_elements, int M, int ef_construction, int rand_seed, int allow_replace_deleted);
    void setEf(HnswIndex *index, size_t ef);
    size_t indexFileSize(HnswIndex *index);
    void saveIndex(HnswIndex *index, char *location);
    HnswIndex *loadIndex(char *location, spaceType space_type, int dim, size_t max_elements, int allow_replace_deleted);

    // add multi-vectors and conresponding labels to index. Returning error codes to indicate error;
    int addPoints(HnswIndex *index, const float *vectors, int rows, size_t *labels, int num_threads, int replace_deleted);
    void markDeleted(HnswIndex *index, size_t label);
    void unmarkDeleted(HnswIndex *index, size_t label);
    void resizeIndex(HnswIndex *index, size_t new_size);
    size_t getMaxElements(HnswIndex *index);
    size_t getCurrentCount(HnswIndex *index);
    int getAllowReplaceDeleted(HnswIndex *index);
    // SearchResult *searchKnn(HnswIndex *index, float **vectors, int rows, int k, filter_func filter, int num_threads);
    SearchResult *searchKnn(HnswIndex *index, const float *flat_vectors, int rows, int k, int num_threads);

    // Get the vector value mapped to label and return it by putting its value in data.
    void getDataByLabel(HnswIndex *index, const size_t label, float *data);
    void freeHNSW(HnswIndex *index);
    void freeResult(SearchResult *result);

#ifdef __cplusplus
}
#endif
