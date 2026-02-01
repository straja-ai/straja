package responseguard

import "strings"

const (
	CategoryDataExfilInstruction           = "data_exfil_instruction"
	CategoryUnsafeActionInstruction        = "unsafe_action_instruction"
	CategoryPrivilegeEscalationInstruction = "privilege_escalation_instruction"
)

func mapCategory(toolGateCategory string) string {
	switch strings.ToLower(strings.TrimSpace(toolGateCategory)) {
	case "data_exfil":
		return CategoryDataExfilInstruction
	case "unsafe_action":
		return CategoryUnsafeActionInstruction
	case "privilege_escalation":
		return CategoryPrivilegeEscalationInstruction
	default:
		return ""
	}
}
