package strajaguard

import "testing"

func TestParseBPETemplateSingleAndApply(t *testing.T) {
	specialIDs := map[string]int64{
		"[CLS]": 101,
		"[SEP]": 102,
	}
	single := []map[string]specialTokenMeta{
		{"SpecialToken": {ID: "[CLS]"}},
		{"Sequence": {ID: "A"}},
		{"SpecialToken": {ID: "[SEP]"}},
	}

	tpl := parseBPETemplateSingle("TemplateProcessing", single, specialIDs)
	if len(tpl) != 3 {
		t.Fatalf("template len: got=%d want=3", len(tpl))
	}
	if tpl[0].isSequence || tpl[0].specialID != 101 {
		t.Fatalf("template[0] mismatch: %+v", tpl[0])
	}
	if !tpl[1].isSequence {
		t.Fatalf("template[1] should be sequence: %+v", tpl[1])
	}
	if tpl[2].isSequence || tpl[2].specialID != 102 {
		t.Fatalf("template[2] mismatch: %+v", tpl[2])
	}

	got := (&BPETokenizer{template: tpl}).applyTemplate([]int64{11, 12, 13})
	want := []int64{101, 11, 12, 13, 102}
	if len(got) != len(want) {
		t.Fatalf("applied len: got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("applied[%d]: got=%d want=%d", i, got[i], want[i])
		}
	}
}
