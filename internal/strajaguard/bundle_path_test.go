package strajaguard

import "testing"

func TestResolveBundlePathBlocksTraversal(t *testing.T) {
	_, err := resolveBundlePath("/tmp/bundle", "../evil")
	if err == nil {
		t.Fatalf("expected traversal to be rejected")
	}
	_, err = resolveBundlePath("/tmp/bundle", "/abs/path")
	if err == nil {
		t.Fatalf("expected absolute path to be rejected")
	}
}

func TestResolveBundlePathAllowsSafe(t *testing.T) {
	got, err := resolveBundlePath("/tmp/bundle", "tokenizer/vocab.txt")
	if err != nil {
		t.Fatalf("expected safe path, got %v", err)
	}
	if got == "" {
		t.Fatalf("expected non-empty path")
	}
}
