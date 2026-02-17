package strajad

func safeHNSWTopK(limit, currentCount, activeCount, efSearch int) int {
	if limit <= 0 || currentCount <= 0 {
		return 0
	}
	k := limit
	if k > currentCount {
		k = currentCount
	}
	if activeCount > 0 && k > activeCount {
		k = activeCount
	}
	if efSearch > 0 && k > efSearch {
		k = efSearch
	}
	if k < 1 {
		return 0
	}
	return k
}
