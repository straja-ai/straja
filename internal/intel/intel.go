package intel

import "context"

// CategoryResult is a coarse structured output for one risk category.
type CategoryResult struct {
    Hit    bool
    Score  float64  // 0..1, for now you can keep it 1.0 when Hit == true
    Labels []string // e.g. ["pii.email", "pii.iban"]
}

// Result groups all category signals for a given input/output.
type Result struct {
    Categories map[string]CategoryResult
}

// Status describes the current intelligence engine state.
type Status struct {
    Enabled       bool
    BundleID      string
    BundleVersion string
}

// Engine is the generic intelligence engine interface.
type Engine interface {
    Status() Status

    AnalyzeInput(ctx context.Context, text string) (*Result, error)
    AnalyzeOutput(ctx context.Context, text string) (*Result, error)
}