package telemetry

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"
)

var denyKeys = []string{
	"prompt",
	"content",
	"authorization",
	"api_key",
	"token",
	"email",
	"phone",
	"iban",
	"credit_card",
}

// SafeAttributes filters out unsafe keys/values and returns OTEL attributes.
func SafeAttributes(values map[string]interface{}) []attribute.KeyValue {
	if len(values) == 0 {
		return nil
	}
	var attrs []attribute.KeyValue
	for k, v := range values {
		lk := strings.ToLower(k)
		skip := false
		for _, bad := range denyKeys {
			if strings.Contains(lk, bad) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		switch val := v.(type) {
		case string:
			if len(val) > 512 {
				continue
			}
			attrs = append(attrs, attribute.String(k, val))
		case bool:
			attrs = append(attrs, attribute.Bool(k, val))
		case int:
			attrs = append(attrs, attribute.Int(k, val))
		case int64:
			attrs = append(attrs, attribute.Int64(k, val))
		case float64:
			attrs = append(attrs, attribute.Float64(k, val))
		case []string:
			attrs = append(attrs, attribute.StringSlice(k, truncateStrings(val, 32)))
		case []int:
			ints := val
			if len(ints) > 32 {
				ints = ints[:32]
			}
			var conv []int64
			for _, i := range ints {
				conv = append(conv, int64(i))
			}
			attrs = append(attrs, attribute.Int64Slice(k, conv))
		default:
			// unsupported types ignored for safety
		}
	}
	return attrs
}

func truncateStrings(in []string, limit int) []string {
	if len(in) <= limit {
		return in
	}
	return in[:limit]
}
