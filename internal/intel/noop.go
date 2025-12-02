package intel

import "context"

type noopEngine struct{}

func NewNoop() Engine {
    return &noopEngine{}
}

func (e *noopEngine) Status() Status {
    return Status{
        Enabled:       false,
        BundleID:      "",
        BundleVersion: "",
    }
}

func (e *noopEngine) AnalyzeInput(ctx context.Context, text string) (*Result, error) {
    return &Result{Categories: map[string]CategoryResult{}}, nil
}

func (e *noopEngine) AnalyzeOutput(ctx context.Context, text string) (*Result, error) {
    return &Result{Categories: map[string]CategoryResult{}}, nil
}