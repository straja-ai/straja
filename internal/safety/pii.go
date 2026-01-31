package safety

// PIIEntity represents a detected PII span with byte offsets.
type PIIEntity struct {
	EntityType string `json:"entity_type"`
	StartByte  int    `json:"start_byte"`
	EndByte    int    `json:"end_byte"`
	Source     string `json:"source"`
}
