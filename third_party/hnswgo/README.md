# HNSWGO
This is a golang binding of [hnswlib](https://github.com/nmslib/hnswlib). 
For more information, please follow [hnswlib](https://github.com/nmslib/hnswlib) and 
[Efficient and robust approximate nearest neighbor search using Hierarchical Navigable Small World graphs.](https://arxiv.org/abs/1603.09320).

## Build

CGO is required to be enabled and c, c++ compiler is required to build this package.

```
go get github.com/oligo/hnswgo
```

## Usage and config

See `example/example.go` or test codes to see usage. 
For detailed information, please refer to the project's documentation at [pkg.go.dev](https://pkg.go.dev/github.com/oligo/hnswgo).


Some important arguments are listed below:


| argument       | type | |
| -------------- | ---- | ----- |
| dim            | int  | vector dimension |
| M              | int  | see[ALGO_PARAMS.md](https://github.com/nmslib/hnswlib/blob/master/ALGO_PARAMS.md) |
| efConstruction | int  | see[ALGO_PARAMS.md](https://github.com/nmslib/hnswlib/blob/master/ALGO_PARAMS.md) |
| randomSeed     | int  | random seed for hnsw |
| maxElements    | int  | max records in data |
| spaceType      | str  | |

| spaceType | distance          |
| --------- |:-----------------:|
| ip        | inner product     |
| cosine    | cosine similarity |
| l2        | l2                |


HNSWGO implements the main hnsw API，Brute force index is not implemented as it is rarely used.

For more information, please consult documents of the [hnswlib projects](https://github.com/nmslib/hnswlib).

# References
Malkov, Yu A., and D. A. Yashunin. "Efficient and robust approximate nearest neighbor search using Hierarchical Navigable Small World graphs." TPAMI, preprint: [https://arxiv.org/abs/1603.09320]
