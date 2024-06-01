package outbound

import (
	"context"
	"regexp"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

type myGroupAdapter struct {
	ctx             context.Context
	tags            []string
	uses            []string
	useAllProviders bool
	includes        []string
	excludes        string
	types           []string
	ports           map[int]bool
	providers       map[string]adapter.OutboundProvider
}

func CheckType(types []string) bool {
	return common.All(types, func(it string) bool {
		switch it {
		case C.TypeTor, C.TypeSSH, C.TypeHTTP, C.TypeSOCKS, C.TypeTUIC, C.TypeVMess, C.TypeVLESS, C.TypeTrojan, C.TypeShadowTLS, C.TypeShadowsocks, C.TypeShadowsocksR, C.TypeHysteria, C.TypeHysteria2, C.TypeWireGuard:
			return true
		}
		return false
	})
}

func CreatePortsMap(ports []string) (map[int]bool, error) {
	portReg1 := regexp.MustCompile(`^\d+$`)
	portReg2 := regexp.MustCompile(`^(\d*):(\d*)$`)
	portMap := map[int]bool{}
	for i, portRaw := range ports {
		result := portReg1.FindStringSubmatch(portRaw)
		if len(result) > 0 {
			port, _ := strconv.Atoi(portRaw)
			if port < 0 || port > 65535 {
				return nil, E.New("invalid ports item[", i, "]")
			}
			portMap[port] = true
			continue
		}
		if portRaw == ":" {
			return nil, E.New("invalid ports item[", i, "]")
		}
		result = portReg2.FindStringSubmatch(portRaw)
		if len(result) > 0 {
			start, _ := strconv.Atoi(result[1])
			end, _ := strconv.Atoi(result[2])
			if start < 0 || start > 65535 {
				return nil, E.New("invalid ports item[", i, "]")
			}
			if end < 0 || end > 65535 {
				return nil, E.New("invalid ports item[", i, "]")
			}
			if end == 0 {
				end = 65535
			}
			if start > end {
				return nil, E.New("invalid ports item[", i, "]")
			}
			for port := start; port <= end; port++ {
				portMap[port] = true
			}
			continue
		}
		return nil, E.New("invalid ports item[", i, "]")
	}
	return portMap, nil
}

func (s *myGroupAdapter) OutboundFilter(out adapter.Outbound) bool {
	return TestIncludes(out.Tag(), s.includes) && TestExcludes(out.Tag(), s.excludes) && TestTypes(out.Type(), s.types) && TestPorts(out.Port(), s.ports)
}

func TestIncludes(tag string, includes []string) bool {
	return common.All(includes, func(it string) bool {
		reg := regexp.MustCompile("(?i)" + it)
		return len(reg.FindStringIndex(tag)) != 0
	})
}

func TestExcludes(tag string, excludes string) bool {
	if excludes == "" {
		return true
	}
	reg := regexp.MustCompile("(?i)" + excludes)
	return len(reg.FindStringIndex(tag)) == 0
}

func TestTypes(oType string, types []string) bool {
	if len(types) == 0 {
		return true
	}
	return common.Any(types, func(it string) bool {
		return oType == it
	})
}

func TestPorts(port int, ports map[int]bool) bool {
	if port == 0 || len(ports) == 0 {
		return true
	}
	_, ok := ports[port]
	return ok
}
