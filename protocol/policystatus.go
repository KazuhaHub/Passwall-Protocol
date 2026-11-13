package protocol

import "fmt"

// PolicyStatus is the agent's observation of the destination policy, and only
// that. Like the rest of NodeReport it says "this is what I did with digest D",
// never "this is my policy": PSP compares Digest with the one it computed, so
// confirmation cannot degrade into PSP agreeing with itself.
type PolicyStatus struct {
	// Digest is PolicyDigest of the policy this status is about: the deployed one
	// when applied, the refused one when rejected. Empty means none: an applied
	// status with an empty Digest is valid and says the agent holds no policy
	// (it was removed, or none was ever sent), which is a state worth reporting
	// because PSP compares it with what it expects the agent to hold.
	Digest string `json:"digest"`
	// State is PolicyStateApplied or PolicyStateRejected.
	State string `json:"state"`
	// IssueCode says why a policy was rejected, and is empty otherwise.
	IssueCode string `json:"issue_code,omitempty"`
	// Listeners are the inbounds whose sniffing cannot support the policy's
	// domain or protocol rules. Present only with
	// IssueDestinationPolicySniffingInsufficient.
	Listeners []ListenerKey `json:"listeners,omitempty"`
}

const (
	PolicyStateApplied  = "applied"
	PolicyStateRejected = "rejected"

	// IssueDestinationPolicyRejected means the node refused the policy as a
	// whole (it did not validate, or the core would not load it).
	IssueDestinationPolicyRejected = "destination_policy_rejected"
	// IssueDestinationPolicySniffingInsufficient means the policy needs sniffed
	// domains or protocols on listeners whose sniffing cannot supply them.
	// PolicyStatus.Listeners names them.
	IssueDestinationPolicySniffingInsufficient = "destination_policy_sniffing_insufficient"
)

// ValidatePolicyStatus checks a status in isolation. The receiver runs it on
// the subtree, not through ValidateNodeReportBase: a bad status must be
// reported as that, without costing the node its whole report.
func ValidatePolicyStatus(status PolicyStatus) error {
	switch status.State {
	case PolicyStateApplied, PolicyStateRejected:
	default:
		return fmt.Errorf("policy status state %q is not applied or rejected", status.State)
	}
	if status.Digest != "" {
		if err := validateDigest(status.Digest); err != nil {
			return fmt.Errorf("policy status digest: %w", err)
		}
	}
	if status.State == PolicyStateApplied {
		if status.IssueCode != "" || len(status.Listeners) > 0 {
			return fmt.Errorf("an applied policy status carries no issue code or listeners")
		}
		return nil
	}
	if len(status.IssueCode) > MaxIssueCodeBytes {
		return fmt.Errorf("policy status issue code exceeds %d bytes", MaxIssueCodeBytes)
	}
	switch status.IssueCode {
	case IssueDestinationPolicyRejected, IssueDestinationPolicySniffingInsufficient:
	default:
		return fmt.Errorf("a rejected policy status needs issue code %s or %s",
			IssueDestinationPolicyRejected, IssueDestinationPolicySniffingInsufficient)
	}
	if len(status.Listeners) > MaxPolicyStatusListeners {
		return fmt.Errorf("policy status lists %d listeners, maximum is %d", len(status.Listeners), MaxPolicyStatusListeners)
	}
	if len(status.Listeners) > 0 && status.IssueCode != IssueDestinationPolicySniffingInsufficient {
		return fmt.Errorf("policy status listeners are only meaningful with %s", IssueDestinationPolicySniffingInsufficient)
	}
	// The code exists to say WHICH inbounds cannot sniff; with none named it
	// sends an operator looking for a problem it does not locate.
	if status.IssueCode == IssueDestinationPolicySniffingInsufficient && len(status.Listeners) == 0 {
		return fmt.Errorf("%s names at least one listener", IssueDestinationPolicySniffingInsufficient)
	}
	// Sorted and duplicate-free, so one set of listeners is one encoding.
	if err := validateKeys("policy status listeners", status.Listeners, ListenerKey.RowID); err != nil {
		return err
	}
	return nil
}
