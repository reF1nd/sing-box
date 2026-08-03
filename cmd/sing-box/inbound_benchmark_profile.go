//go:build with_inbound_benchmark_profile

package main

import "runtime"

func init() {
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
}
