//go:build with_ebpf && (linux || android)

package ebpf

import (
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

const maintenanceMaxFailures = 5

type maintenanceScheduleConfig struct {
	watchdog     time.Duration
	continuation time.Duration
	cooldown     time.Duration
	pressure     time.Duration
	maxFailures  uint
}

var (
	tcAssignmentMaintenanceSchedule = maintenanceScheduleConfig{
		watchdog:     time.Minute,
		continuation: 100 * time.Millisecond,
		cooldown:     5 * time.Second,
		pressure:     time.Second,
		maxFailures:  maintenanceMaxFailures,
	}
	sharedFlowMaintenanceSchedule = maintenanceScheduleConfig{
		watchdog:     time.Minute,
		continuation: 100 * time.Millisecond,
		cooldown:     5 * time.Second,
		pressure:     time.Second,
		maxFailures:  maintenanceMaxFailures,
	}
)

type mapPressureHysteresis struct {
	enterPercent uint64
	exitPercent  uint64
	exitRounds   uint32
}

func mapUsageAtLeastPercent(usage commonEBPF.MapUsage, percent uint64) bool {
	return usage.Capacity != 0 && uint64(usage.Entries)*100 >= uint64(usage.Capacity)*percent
}

func mapUsageAbovePercent(usage commonEBPF.MapUsage, percent uint64) bool {
	return usage.Capacity != 0 && uint64(usage.Entries)*100 > uint64(usage.Capacity)*percent
}

func updateMapPressure(
	active bool,
	belowExitRounds uint32,
	usage commonEBPF.MapUsage,
	policy mapPressureHysteresis,
) (bool, uint32, bool, bool) {
	if usage.Capacity == 0 {
		return active, 0, false, false
	}
	if !active {
		if mapUsageAtLeastPercent(usage, policy.enterPercent) {
			return true, 0, true, false
		}
		return false, 0, false, false
	}
	if mapUsageAbovePercent(usage, policy.exitPercent) {
		return true, 0, false, false
	}
	belowExitRounds++
	if belowExitRounds < policy.exitRounds {
		return true, belowExitRounds, false, false
	}
	return false, 0, false, true
}

func resetMaintenanceTimer(timer **time.Timer, continuation *<-chan time.Time, delay time.Duration) {
	if *timer == nil {
		*timer = time.NewTimer(delay)
	} else {
		if !(*timer).Stop() {
			select {
			case <-(*timer).C:
			default:
			}
		}
		(*timer).Reset(delay)
	}
	*continuation = (*timer).C
}

// maintenanceJob owns the timer and continuation channel for one bounded
// maintenance stream. TC assignments and shared packet-rewrite flows use the
// same lifecycle rules, while retaining independent schedules and pressure
// state.
type maintenanceJob struct {
	schedule     maintenanceSchedule
	timer        *time.Timer
	continuation <-chan time.Time
}

func newMaintenanceJob(config maintenanceScheduleConfig) maintenanceJob {
	return maintenanceJob{schedule: maintenanceSchedule{config: config}}
}

func (j *maintenanceJob) reset(delay time.Duration) {
	resetMaintenanceTimer(&j.timer, &j.continuation, delay)
}

func (j *maintenanceJob) finish(now time.Time, complete, pressure bool, err error) {
	if delay := j.schedule.finish(now, complete, pressure, err); delay > 0 {
		j.reset(delay)
	} else {
		j.stop()
	}
}

func (j *maintenanceJob) stop() {
	if j.timer != nil {
		j.timer.Stop()
	}
	j.continuation = nil
}

// One instance belongs to the active worker, whether standalone or shared.
// Wakeups coalesce until the deadline; traffic never postpones that deadline.
type maintenanceSchedule struct {
	config   maintenanceScheduleConfig
	next     time.Time
	failures uint
}

func (s *maintenanceSchedule) delay(now time.Time) time.Duration {
	return max(0, s.next.Sub(now))
}

func (s *maintenanceSchedule) finish(now time.Time, complete, pressure bool, err error) time.Duration {
	delay := s.config.cooldown
	if err != nil {
		s.failures = min(s.failures+1, s.config.maxFailures)
		delay = min(s.config.cooldown<<(s.failures-1), s.config.watchdog)
	} else if !complete {
		s.failures = 0
		delay = s.config.continuation
	} else if pressure {
		s.failures = 0
		delay = s.config.pressure
	} else {
		s.failures = 0
	}
	s.next = now.Add(delay)
	if err != nil || !complete || pressure {
		return delay
	}
	return 0
}
