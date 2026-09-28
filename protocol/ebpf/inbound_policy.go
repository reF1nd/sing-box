//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"reflect"
	"strings"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
	"go4.org/netipx"
)

// Each scope owns its callbacks, expected generation, confirmed generation and
// retry state. A failed apply never advances the confirmed policy.
type bypassRuleSetState struct {
	ruleSets                                   []adapter.RuleSet
	callbacks                                  []*list.Element[adapter.RuleSetUpdateCallback]
	started                                    bool
	policy, expectedPolicy                     []commonEBPF.CIDRDecision
	policyVersion, expectedVersion, retryCount uint64
	needsRetry, inconsistent                   bool
	tc, cgroup, shared                         bypassRuleSetBackendVersion
}

type bypassRuleSetBackendVersion struct {
	version uint64
	known   bool
}

type destinationDecisionApply func([]commonEBPF.CIDRDecision) (bool, error)
type bypassPolicyBackend struct {
	name            string
	apply           destinationDecisionApply
	requiresRebuild func() bool
	state           *bypassRuleSetBackendVersion
}
type bypassCIDRAppliedBackend struct {
	name   string
	revert func() error
}

func (i *Inbound) policyBackends(shared bool) []bypassPolicyBackend {
	var targets []bypassPolicyBackend
	if shared {
		if backend := i.tcBackend(); i.sharedSocketAssignEnabled() && backend != nil {
			targets = append(targets, bypassPolicyBackend{"TC", backend.UpdateSharedDestinationDecisions, backend.RequiresRebuild, &i.sharedBypassRules.tc})
		}
		if runtime := i.sharedRewriteInstance(); i.sharedRewriteEnabled() && runtime != nil {
			if backend := runtime.sharedBackendInstance(); backend != nil {
				targets = append(targets, bypassPolicyBackend{"packet_rewrite", backend.UpdateDestinationDecisions, backend.RequiresRebuild, &i.sharedBypassRules.shared})
			}
		}
	} else {
		if backend := i.tcBackend(); i.localSocketAssignEnabled() && backend != nil {
			targets = append(targets, bypassPolicyBackend{"TC", backend.UpdateLocalDestinationDecisions, backend.RequiresRebuild, &i.localBypassRules.tc})
		}
		if backend := i.cgroupBackendInstance(); i.localCgroupEnabled() && backend != nil {
			targets = append(targets, bypassPolicyBackend{"cgroup", backend.UpdateDestinationDecisions, backend.RequiresRebuild, &i.localBypassRules.cgroup})
		}
	}
	return targets
}

func (i *Inbound) ruleSetScope(shared bool) (*bypassRuleSetState, string, []commonEBPF.CIDRDecision) {
	if shared {
		return &i.sharedBypassRules, "shared.bypass_rule_set", i.sharedInitialDestinations
	}
	return &i.localBypassRules, "local.bypass_rule_set", i.localInitialDestinations
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	for _, shared := range []bool{false, true} {
		state, _, _ := i.ruleSetScope(shared)
		if state.started {
			continue
		}
		for _, ruleSet := range state.ruleSets {
			ruleSet.IncRef()
			state.callbacks = append(state.callbacks, ruleSet.RegisterCallback(func(adapter.RuleSet) { i.updateRuleSet(shared) }))
		}
		state.started = true
		if err := i.refreshRuleSetsLocked(shared, true); err != nil {
			i.stopBypassRuleSetsLocked()
			return err
		}
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}
func (i *Inbound) stopBypassRuleSetsLocked() {
	for _, state := range []*bypassRuleSetState{&i.localBypassRules, &i.sharedBypassRules} {
		if !state.started {
			continue
		}
		for index, ruleSet := range state.ruleSets {
			ruleSet.UnregisterCallback(state.callbacks[index])
			ruleSet.DecRef()
		}
		state.callbacks = nil
		state.started = false
	}
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet)       { i.updateRuleSet(false) }
func (i *Inbound) updateSharedBypassRuleSet(adapter.RuleSet) { i.updateRuleSet(true) }
func (i *Inbound) updateRuleSet(shared bool) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	state, name, _ := i.ruleSetScope(shared)
	if !state.started {
		return
	}
	err := i.refreshRuleSetsLocked(shared, false)
	state.needsRetry = err != nil
	if err != nil {
		i.policyWarnings.warn(i.logger, "refresh ", name, ": ", err)
		i.notifyTCInterfaceUpdate()
	}
}

func (i *Inbound) retryBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	return max(i.retryRuleSetLocked(false), i.retryRuleSetLocked(true))
}
func (i *Inbound) retryLocalBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	return i.retryRuleSetLocked(false)
}
func (i *Inbound) retryRuleSetLocked(shared bool) tcSharedRewriteOutcome {
	state, name, _ := i.ruleSetScope(shared)
	if !state.started {
		return tcSharedRewriteSettled
	}
	requiresRebuild := func() bool {
		for _, backend := range i.policyBackends(shared) {
			if backend.requiresRebuild() {
				return true
			}
		}
		return false
	}
	if requiresRebuild() {
		state.needsRetry = false
		return tcSharedRewriteUnrecoverable
	}
	if !state.needsRetry {
		return tcSharedRewriteSettled
	}
	state.retryCount++
	if err := i.refreshRuleSetsLocked(shared, false); err != nil {
		i.policyWarnings.warn(i.logger, "retry ", name, ": ", err)
		if requiresRebuild() {
			state.needsRetry = false
			return tcSharedRewriteUnrecoverable
		}
		return tcSharedRewriteRecoverable
	}
	state.needsRetry = false
	return tcSharedRewriteSettled
}

func (i *Inbound) refreshBypassRuleSetsLocked(startup bool) error {
	return i.refreshRuleSetsLocked(false, startup)
}
func (i *Inbound) refreshSharedBypassRuleSetsLocked(startup bool) error {
	return i.refreshRuleSetsLocked(true, startup)
}
func (i *Inbound) refreshRuleSetsLocked(shared, startup bool) error {
	state, name, initial := i.ruleSetScope(shared)
	var prefixes []netip.Prefix
	for _, ruleSet := range state.ruleSets {
		ipSets := ruleSet.ExtractIPSet()
		if startup && len(ipSets) == 0 {
			i.logger.Warn(name, ": no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		for _, ipSet := range ipSets {
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	dynamic, err := i.compileBypassCIDRDecisions(prefixes)
	if err != nil {
		return err
	}
	policy, err := i.combineDestinationDecisions(initial, dynamic)
	if err != nil {
		return err
	}
	return i.applyRuleSetPolicyLocked(shared, policy)
}

func revertBypassCIDRBackends(applied []bypassCIDRAppliedBackend, warn func(string, error)) []string {
	var failed []string
	for index := len(applied) - 1; index >= 0; index-- {
		if err := applied[index].revert(); err != nil {
			failed = append(failed, applied[index].name)
			warn(applied[index].name, err)
		}
	}
	return failed
}
func (i *Inbound) applyBypassCIDRPolicyLocked(policy []commonEBPF.CIDRDecision) error {
	return i.applyRuleSetPolicyLocked(false, policy)
}
func (i *Inbound) applySharedBypassCIDRPolicyLocked(policy []commonEBPF.CIDRDecision) error {
	return i.applyRuleSetPolicyLocked(true, policy)
}
func (i *Inbound) applyRuleSetPolicyLocked(shared bool, policy []commonEBPF.CIDRDecision) error {
	state, name, _ := i.ruleSetScope(shared)
	return i.applyRuleSetPolicyToBackends(state, name, policy, i.policyBackends(shared))
}

func (i *Inbound) applyRuleSetPolicyToBackends(state *bypassRuleSetState, name string, policy []commonEBPF.CIDRDecision, targets []bypassPolicyBackend) error {
	if !reflect.DeepEqual(state.expectedPolicy, policy) {
		state.expectedVersion++
	}
	state.expectedPolicy = policy
	var applied []bypassCIDRAppliedBackend
	for _, backend := range targets {
		if _, err := backend.apply(policy); err != nil {
			if backend.requiresRebuild() {
				backend.state.known = false
				state.inconsistent = true
			}
			failed := revertBypassCIDRBackends(applied, func(target string, err error) {
				i.policyWarnings.warn(i.logger, name, ": revert ", target, ": ", err)
			})
			if len(failed) > 0 {
				state.inconsistent = true
				return E.Cause(err, name+" left inconsistent on: "+strings.Join(failed, ", "))
			}
			return err
		}
		*backend.state = bypassRuleSetBackendVersion{version: state.expectedVersion, known: true}
		applied = append(applied, bypassCIDRAppliedBackend{name: backend.name, revert: func() error {
			if _, err := backend.apply(state.policy); err != nil {
				backend.state.known = false
				return err
			}
			*backend.state = bypassRuleSetBackendVersion{version: state.policyVersion, known: true}
			return nil
		}})
	}
	state.policy, state.policyVersion = policy, state.expectedVersion
	state.inconsistent = false
	return nil
}

func (i *Inbound) compileBypassCIDRDecisions(prefixes []netip.Prefix) ([]commonEBPF.CIDRDecision, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		builder.AddPrefix(prefix.Masked())
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil, E.Cause(err, "compile eBPF bypass CIDR decisions")
	}
	canonical := set.Prefixes()
	decisions := make([]commonEBPF.CIDRDecision, 0, len(canonical))
	for _, prefix := range canonical {
		decisions = append(decisions, commonEBPF.CIDRDecision{Prefix: prefix, Action: commonEBPF.DecisionPass})
	}
	return decisions, nil
}

func (i *Inbound) combineDestinationDecisions(
	static, dynamic []commonEBPF.CIDRDecision,
) ([]commonEBPF.CIDRDecision, error) {
	prefixes := make([]netip.Prefix, 0, len(static)+len(dynamic))
	for _, decision := range append(append([]commonEBPF.CIDRDecision(nil), static...), dynamic...) {
		if decision.Action != commonEBPF.DecisionPass || !decision.Prefix.IsValid() {
			return nil, E.New("invalid eBPF destination pass decision")
		}
		prefixes = append(prefixes, decision.Prefix)
	}
	return i.compileBypassCIDRDecisions(prefixes)
}
