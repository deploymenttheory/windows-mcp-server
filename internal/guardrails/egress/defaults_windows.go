//go:build windows && (amd64 || arm64)

package egress

import (
	"fmt"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/windowsfirewall"
	"github.com/deploymenttheory/windows-mcp-server/internal/guardrails/contain"
)

// blockedProfiles are the firewall profiles global mode flips.
//
// The same three the kill ladder isolates, deliberately: leaving one untouched
// would mean a machine that is default-deny at home and wide open on a domain
// network, which is not a posture anyone asked for.
var blockedProfiles = []windowsfirewall.NET_FW_PROFILE_TYPE2{
	windowsfirewall.NET_FW_PROFILE2_DOMAIN,
	windowsfirewall.NET_FW_PROFILE2_PRIVATE,
	windowsfirewall.NET_FW_PROFILE2_PUBLIC,
}

// savedOutbound records a profile's prior default outbound action, so restoring
// puts back what was there rather than assuming it was Allow. An operator whose
// machine already blocked outbound by policy must not have that silently undone
// by this server exiting.
type savedOutbound struct {
	Profile int32 `json:"profile"`
	Action  int32 `json:"action"`
}

// readDefaultOutbound snapshots the current default outbound action per profile.
func readDefaultOutbound() ([]savedOutbound, error) {
	var saved []savedOutbound
	if err := contain.WithCOMThread(func() error {
		policy, release, err := contain.NewFwPolicy()
		if err != nil {
			return fmt.Errorf("open firewall policy: %w", err)
		}
		defer release()
		for _, profile := range blockedProfiles {
			action, err := policy.Get_DefaultOutboundAction(profile)
			if err != nil {
				return fmt.Errorf("read default outbound action (profile %d): %w", profile, err)
			}
			saved = append(saved, savedOutbound{Profile: int32(profile), Action: int32(action)})
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("snapshot default outbound actions: %w", err)
	}
	return saved, nil
}

// setDefaultOutbound applies one action to every profile.
func setDefaultOutbound(action windowsfirewall.NET_FW_ACTION) error {
	if err := contain.WithCOMThread(func() error {
		policy, release, err := contain.NewFwPolicy()
		if err != nil {
			return fmt.Errorf("open firewall policy: %w", err)
		}
		defer release()
		for _, profile := range blockedProfiles {
			if err := policy.Put_DefaultOutboundAction(profile, action); err != nil {
				return fmt.Errorf("set default outbound action (profile %d): %w", profile, err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apply default outbound action: %w", err)
	}
	return nil
}

// restoreDefaultOutbound puts back the snapshotted actions.
//
// Every profile is attempted even when one fails, and the first error is
// reported afterwards: giving up halfway would leave a machine blocked on the
// profiles not yet reached, which is precisely the state this is undoing.
func restoreDefaultOutbound(saved []savedOutbound) error {
	if len(saved) == 0 {
		return nil
	}
	if err := contain.WithCOMThread(func() error {
		policy, release, err := contain.NewFwPolicy()
		if err != nil {
			return fmt.Errorf("open firewall policy: %w", err)
		}
		defer release()
		var firstErr error
		for _, s := range saved {
			profile := windowsfirewall.NET_FW_PROFILE_TYPE2(s.Profile)
			action := windowsfirewall.NET_FW_ACTION(s.Action)
			if err := policy.Put_DefaultOutboundAction(profile, action); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("restore default outbound action (profile %d): %w", profile, err)
			}
		}
		return firstErr
	}); err != nil {
		return fmt.Errorf("restore default outbound actions: %w", err)
	}
	return nil
}
