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
)

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.bypassRuleSetStarted {
		return nil
	}
	i.bypassRuleSetCallbacks = make([]*list.Element[adapter.RuleSetUpdateCallback], 0, len(i.bypassRuleSet))
	for _, ruleSet := range i.bypassRuleSet {
		ruleSet.IncRef()
		i.bypassRuleSetCallbacks = append(i.bypassRuleSetCallbacks, ruleSet.RegisterCallback(i.updateBypassRuleSet))
	}
	i.bypassRuleSetStarted = true
	err := i.refreshBypassRuleSetsLocked(true)
	if err != nil {
		i.stopBypassRuleSetsLocked()
		return err
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if !i.bypassRuleSetStarted {
		return
	}
	for ruleSetIndex, ruleSet := range i.bypassRuleSet {
		if ruleSetIndex < len(i.bypassRuleSetCallbacks) {
			ruleSet.UnregisterCallback(i.bypassRuleSetCallbacks[ruleSetIndex])
		}
		ruleSet.DecRef()
	}
	i.bypassRuleSetCallbacks = nil
	i.bypassRuleSetStarted = false
}

func (i *Inbound) updateBypassRuleSet(adapter.RuleSet) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return
	}
	err := i.refreshBypassRuleSetsLocked(false)
	if err != nil {
		// refreshBypassRuleSetsLocked has already reverted every backend it
		// could; the message below only ever names the update failure
		// itself, since a revert that also failed is reported separately,
		// by name, at the point it happened.
		i.policyWarnings.warn(i.logger, "refresh TC eBPF bypass_rule_set: ", err)
		// A rule-set update is the only thing that would otherwise ever ask
		// for a retry: nothing about this ruleset is guaranteed to change
		// again. retryBypassRuleSetIfNeededLocked picks this back up on the
		// scheduler's next round, but the scheduler only runs a round on a
		// network event or its own drift-check tick (tcDriftCheckInterval,
		// ten minutes) -- setting the flag alone does not make one happen.
		// notifyTCInterfaceUpdate is the same non-blocking wake this
		// package's other event sources already use to get an immediate
		// round out of the update loop instead of waiting on either of
		// those; without it, this failure's own first retry attempt would
		// sit unnoticed for up to ten minutes even though the scheduler's
		// real exponential backoff (seconds, not minutes) is what every
		// other TC failure in this package actually gets.
		i.bypassRuleSetNeedsRetry = true
		i.notifyTCInterfaceUpdate()
		return
	}
	i.bypassRuleSetNeedsRetry = false
}

// retryBypassRuleSetIfNeededLocked is updateTCInterfaces' hook into the
// bypass_rule_set half of this file: it does nothing (and reports settled)
// unless a previous refreshBypassRuleSetsLocked call actually failed, so a
// healthy bypass_rule_set costs this per-round pass nothing beyond the lock
// acquisition and the boolean check.
func (i *Inbound) retryBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.bypassRuleSetStarted {
		return tcSharedRewriteSettled
	}
	if i.bypassRuleSetBackendRequiresRebuildLocked() {
		i.bypassRuleSetNeedsRetry = false
		return tcSharedRewriteUnrecoverable
	}
	if !i.bypassRuleSetNeedsRetry {
		return tcSharedRewriteSettled
	}
	// Counted here, not inside applyBypassCIDRPolicyLocked, so it reflects
	// only calls that are actually retries of a previously-failed apply --
	// refreshBypassRuleSetsLocked's other two call sites (startup, and a
	// rule-set update callback) are not retries even though they share the
	// same underlying apply function.
	i.bypassRuleSetRetryCount++
	if err := i.refreshBypassRuleSetsLocked(false); err != nil {
		// Same reasoning as updateBypassRuleSet's warning: refreshBypassRuleSetsLocked
		// already reverted what it could, and reports what it couldn't separately.
		i.policyWarnings.warn(i.logger, "retry TC eBPF bypass_rule_set refresh: ", err)
		if i.bypassRuleSetBackendRequiresRebuildLocked() {
			i.bypassRuleSetNeedsRetry = false
			return tcSharedRewriteUnrecoverable
		}
		return tcSharedRewriteRecoverable
	}
	i.bypassRuleSetNeedsRetry = false
	return tcSharedRewriteSettled
}

func (i *Inbound) bypassRuleSetBackendRequiresRebuildLocked() bool {
	if backend := i.tcBackend(); backend != nil && backend.RequiresRebuild() {
		return true
	}
	if backend := i.cgroupBackendInstance(); backend != nil && backend.RequiresRebuild() {
		return true
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil && backend.RequiresRebuild() {
			return true
		}
	}
	return false
}

// bypassCIDRAppliedBackend is one backend applyBypassCIDRPolicyLocked has
// already moved to the new policy, along with how to move it back to the
// policy that was live before this refresh, should a later backend in the
// same pass fail.
type bypassCIDRAppliedBackend struct {
	name   string
	revert func() error
}

// bypassRuleSetBackendVersion is one backend's own confirmed position in the
// bypass_rule_set policy version sequence (Inbound.bypassRuleSetPolicyVersion).
// version is the highest policy version this backend's own forward apply or
// compensating revert last actually completed successfully. known is false
// whenever the most recent operation attempted on this backend -- which, by
// construction, is always a revert, since a backend whose forward apply
// itself failed is never added to applied in the first place -- did not
// complete successfully, leaving this backend's true state unconfirmed:
// version then still names the last point it was confirmed at, not a claim
// about what it is actually running now. A caller must treat known=false as
// "unknown", not silently trust version as current.
type bypassRuleSetBackendVersion struct {
	version uint64
	known   bool
}

type bypassCIDRPolicyBackend interface {
	UpdateCompiledBypassCIDR(policy commonEBPF.BypassCIDRPolicy) (bool, error)
	RequiresRebuild() bool
}

func (i *Inbound) applyBypassCIDRBackend(
	name string,
	backend bypassCIDRPolicyBackend,
	state *bypassRuleSetBackendVersion,
	policy commonEBPF.BypassCIDRPolicy,
	previous commonEBPF.BypassCIDRPolicy,
	version uint64,
	previousVersion uint64,
) (bypassCIDRAppliedBackend, error) {
	if _, err := backend.UpdateCompiledBypassCIDR(policy); err != nil {
		if backend.RequiresRebuild() {
			state.known = false
			i.bypassRuleSetInconsistent = true
		}
		return bypassCIDRAppliedBackend{}, err
	}
	*state = bypassRuleSetBackendVersion{version: version, known: true}
	return bypassCIDRAppliedBackend{
		name: name,
		revert: func() error {
			_, err := backend.UpdateCompiledBypassCIDR(previous)
			if err != nil {
				state.known = false
				return err
			}
			*state = bypassRuleSetBackendVersion{version: previousVersion, known: true}
			return nil
		},
	}, nil
}

// revertBypassCIDRBackends reverts every already-applied backend, most
// recently applied first, and reports the name of each one whose own revert
// call also failed. It always attempts every entry rather than stopping at
// the first failure, so one backend refusing to revert does not leave an
// earlier one stuck on the new policy for no reason -- each backend's revert
// is independent of the others', exactly like its forward update was.
func revertBypassCIDRBackends(applied []bypassCIDRAppliedBackend, warn func(name string, err error)) []string {
	var failed []string
	for index := len(applied) - 1; index >= 0; index-- {
		if err := applied[index].revert(); err != nil {
			failed = append(failed, applied[index].name)
			warn(applied[index].name, err)
		}
	}
	return failed
}

// refreshBypassRuleSetsLocked compiles the current bypass_rule_set contents
// into one policy and hands it to applyBypassCIDRPolicyLocked.
func (i *Inbound) refreshBypassRuleSetsLocked(startup bool) error {
	var prefixes []netip.Prefix
	for _, ruleSet := range i.bypassRuleSet {
		ipSets := ruleSet.ExtractIPSet()
		if startup && len(ipSets) == 0 {
			i.logger.Warn("bypass_rule_set: no destination IP CIDR rules found in rule-set: ", ruleSet.Name())
		}
		for _, ipSet := range ipSets {
			prefixes = append(prefixes, ipSet.Prefixes()...)
		}
	}
	policy, err := i.compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return err
	}
	return i.applyBypassCIDRPolicyLocked(policy)
}

// applyBypassCIDRPolicyLocked applies one compiled policy to every backend
// this inbound has: TC, cgroup, and (unless it mirrors cgroup's own map)
// shared-network. These are independent native objects with independent
// maps, so one succeeding while a later one fails leaves them disagreeing
// about which destinations bypass the proxy -- silently, since nothing else
// notices a map that still holds the previous policy.
//
// This is a best-effort compensating rollback, not an atomic switch: each
// backend's own UpdateCompiledBypassCIDR/SetBypassCIDRState call is already
// crash-safe on its own (see sing-ebpf's per-backend rollback-on-map-error
// handling), so unwinding a partially-applied pass here just means calling
// the same per-backend operation again with the previous policy, which each
// backend computes its own diff against exactly as it would for any other
// update. If a per-backend revert itself fails, that backend's actual state
// is now unknown relative to i.bypassRuleSetPolicy, and this reports exactly
// which backend by name rather than claiming a global "kept previous policy"
// that would no longer be true for it; bypassRuleSetInconsistent records the
// anomaly for diagnostics until a later call applies cleanly everywhere.
func (i *Inbound) applyBypassCIDRPolicyLocked(policy commonEBPF.BypassCIDRPolicy) error {
	previous := i.bypassRuleSetPolicy
	previousVersion := i.bypassRuleSetPolicyVersion
	// version identifies this call's own content, computed against the
	// most recently ATTEMPTED policy (i.bypassRuleSetExpectedPolicy),
	// not the last successfully CONFIRMED one (previous, above). Comparing
	// against the confirmed baseline instead would assign the same version
	// number to two attempts with genuinely different content as long as
	// neither had yet succeeded -- confirmed state only advances on
	// success, so it can lag behind an arbitrary number of distinct failed
	// attempts, each of which still needs its own, distinguishable version.
	// BypassCIDRPolicy's fields are unexported outside sing-ebpf, but
	// reflect.DeepEqual compares them by value regardless of visibility
	// (the same pattern the tests in inbound_policy_test.go already rely
	// on).
	previousExpected := i.bypassRuleSetExpectedPolicy
	previousExpectedVersion := i.bypassRuleSetExpectedVersion
	version := previousExpectedVersion
	if !reflect.DeepEqual(previousExpected, policy) {
		version = previousExpectedVersion + 1
	}
	// Committed unconditionally, before any backend is even attempted: a
	// diagnostics reader watching while this very attempt is in flight (or
	// after it has already failed) must see what this call is trying to
	// converge to, not whatever the last successful attempt happened to be,
	// and a later call (whether a fresh apply or a retry) must compare
	// against THIS content, not go on comparing against a stale one.
	i.bypassRuleSetExpectedPolicy = policy
	i.bypassRuleSetExpectedVersion = version
	// This local version is used for each backend's own per-backend
	// bookkeeping as the loop below runs, since a backend that completes its
	// own forward apply genuinely has moved to this content regardless of
	// what a later backend does. i.bypassRuleSetPolicyVersion itself is only
	// committed at the very end, alongside i.bypassRuleSetPolicy -- both
	// describe "the policy this inbound has actually confirmed applying",
	// and both must move together: a failed pass that gets fully reverted
	// (or even one left partially inconsistent) never updates
	// i.bypassRuleSetPolicy, so the version naming that policy must not
	// advance either, or the two would disagree about which generation is
	// current.
	var applied []bypassCIDRAppliedBackend
	fail := func(cause error) error {
		failedPaths := revertBypassCIDRBackends(applied, func(name string, err error) {
			i.policyWarnings.warn(i.logger, "bypass_rule_set: revert ", name, " to the previous policy: ", err)
		})
		if len(failedPaths) > 0 {
			i.bypassRuleSetInconsistent = true
			return E.Cause(cause, "bypass_rule_set left inconsistent on: "+strings.Join(failedPaths, ", "))
		}
		return cause
	}
	var err error
	if backend := i.tcBackend(); backend != nil {
		var appliedBackend bypassCIDRAppliedBackend
		appliedBackend, err = i.applyBypassCIDRBackend(
			"TC", backend, &i.bypassRuleSetTC, policy, previous, version, previousVersion,
		)
		if err != nil {
			return fail(err)
		}
		applied = append(applied, appliedBackend)
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		var appliedBackend bypassCIDRAppliedBackend
		appliedBackend, err = i.applyBypassCIDRBackend(
			"cgroup", backend, &i.bypassRuleSetCgroup, policy, previous, version, previousVersion,
		)
		if err != nil {
			return fail(err)
		}
		applied = append(applied, appliedBackend)
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil {
			if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
				ipv4Count, ipv6Count := cgroupBackend.BypassCIDRCount()
				if err = backend.SetBypassCIDRState(ipv4Count, ipv6Count); err != nil {
					return fail(err)
				}
				i.bypassRuleSetShared = bypassRuleSetBackendVersion{version: version, known: true}
				previousIPv4Count, previousIPv6Count := previous.Counts()
				applied = append(applied, bypassCIDRAppliedBackend{
					name: "shared",
					revert: func() error {
						revertErr := backend.SetBypassCIDRState(previousIPv4Count, previousIPv6Count)
						if revertErr == nil {
							i.bypassRuleSetShared = bypassRuleSetBackendVersion{version: previousVersion, known: true}
						} else {
							i.bypassRuleSetShared.known = false
						}
						return revertErr
					},
				})
			} else {
				var appliedBackend bypassCIDRAppliedBackend
				appliedBackend, err = i.applyBypassCIDRBackend(
					"shared", backend, &i.bypassRuleSetShared, policy, previous, version, previousVersion,
				)
				if err != nil {
					return fail(err)
				}
				applied = append(applied, appliedBackend)
			}
		}
	}
	i.bypassRuleSetPolicy = policy
	i.bypassRuleSetPolicyVersion = version
	i.bypassRuleSetInconsistent = false
	return nil
}

func (i *Inbound) compileBypassCIDRPolicy(prefixes []netip.Prefix) (commonEBPF.BypassCIDRPolicy, error) {
	policy, err := commonEBPF.CompileBypassCIDRPolicy(prefixes)
	if err != nil {
		return policy, E.Cause(err, "compile TC eBPF bypass CIDR policy")
	}
	return policy, nil
}
