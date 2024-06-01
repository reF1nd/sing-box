package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	O "github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service/pause"
)

type SubInfo struct {
	upload   int64
	download int64
	total    int64
	expire   int64
}

type myProviderAdapter struct {
	ctx     context.Context
	cancel  context.CancelFunc
	router  adapter.Router
	logger  log.ContextLogger
	subInfo SubInfo

	// Common config
	tag                 string
	path                string
	healthcheckUrl      string
	healthcheckInterval time.Duration
	overrideDialer      *option.OverrideDialerOptions
	healchcheckHistory  *urltest.HistoryStorage
	providerType        string
	updateTime          time.Time
	outbounds           []adapter.Outbound
	outboundByTag       map[string]adapter.Outbound
	includes            []string
	excludes            string
	types               []string
	ports               map[int]bool

	// Update cache
	checking        atomic.Bool
	updating        atomic.Bool
	pauseManager    pause.Manager
	lastHealthcheck time.Time
	lastOuts        []option.Outbound

	ticker *time.Ticker
	close  chan struct{}
}

func (a *myProviderAdapter) Tag() string {
	return a.tag
}

func (a *myProviderAdapter) Path() string {
	return a.path
}

func (a *myProviderAdapter) Type() string {
	return a.providerType
}

func (a *myProviderAdapter) UpdateTime() time.Time {
	return a.updateTime
}

func (a *myProviderAdapter) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := a.outboundByTag[tag]
	return outbound, loaded
}

func (a *myProviderAdapter) Outbounds() []adapter.Outbound {
	outbounds := []adapter.Outbound{}
	outbounds = append(outbounds, a.outbounds...)
	return outbounds
}

func (a *myProviderAdapter) firstStart(ports []string) error {
	if !O.CheckType(a.types) {
		return E.New("invalid types")
	}
	if portMap, err := O.CreatePortsMap(ports); err == nil {
		a.ports = portMap
	} else {
		return nil
	}
	if !rw.FileExists(a.path) {
		return nil
	}
	fileInfo, _ := os.Stat(a.path)
	fileModeTime := fileInfo.ModTime()
	info, content := a.getContentFromFile(a.router)
	a.subInfo = info
	a.updateTime = fileModeTime
	outbounds, err := a.parseOutbounds(a.ctx, a.router, decodeBase64Safe(content))
	if err != nil {
		return err
	} else if outbounds == nil {
		return nil
	}
	outboundByTag := make(map[string]adapter.Outbound)
	for _, out := range outbounds {
		tag := out.Tag()
		outboundByTag[tag] = out
	}
	a.outbounds = outbounds
	a.outboundByTag = outboundByTag
	return nil
}

func getFirstLine(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 1 {
		return lines[0], ""
	}
	others := strings.Join(lines[1:], "\n")
	return lines[0], others
}

func (a *myProviderAdapter) SubInfo() map[string]int64 {
	info := make(map[string]int64)
	info["Upload"] = a.subInfo.upload
	info["Download"] = a.subInfo.download
	info["Total"] = a.subInfo.total
	info["Expire"] = a.subInfo.expire
	return info
}

func parseSubInfo(infoString string) (SubInfo, bool) {
	var info SubInfo
	reg := regexp.MustCompile("upload=[+-]?(\\d*);[ \t]*download=[+-]?(\\d*);[ \t]*total=[+-]?(\\d*);[ \t]*expire=[+-]?(\\d*)")
	result := reg.FindStringSubmatch(infoString)
	if len(result) > 0 {
		upload, _ := strconv.Atoi(result[1:][0])
		download, _ := strconv.Atoi(result[1:][1])
		total, _ := strconv.Atoi(result[1:][2])
		expire, _ := strconv.Atoi(result[1:][3])
		info.upload = int64(upload)
		info.download = int64(download)
		info.total = int64(total)
		info.expire = int64(expire)
		return info, true
	}
	return info, false
}

func (a *myProviderAdapter) createOutbounds(ctx context.Context, router adapter.Router, outbounds []option.Outbound) ([]adapter.Outbound, error) {
	outs := []adapter.Outbound{}
	for _, outbound := range outbounds {
		otype := outbound.Type
		tag := outbound.Tag
		switch otype {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest:
			continue
		default:
			out, err := O.New(ctx, router, a.logger, tag, outbound)
			if err != nil {
				E.New("invalid outbound")
				continue
			}
			outs = append(outs, out)
		}
	}
	return outs, nil
}

func getTrimedFile(path string) []byte {
	content, _ := os.ReadFile(path)
	return []byte(trimBlank(string(content)))
}

func trimBlank(str string) string {
	str = strings.Trim(str, " ")
	str = strings.Trim(str, "\a")
	str = strings.Trim(str, "\b")
	str = strings.Trim(str, "\f")
	str = strings.Trim(str, "\r")
	str = strings.Trim(str, "\t")
	str = strings.Trim(str, "\v")
	return str
}

func (p *myProviderAdapter) getContentFromFile(router adapter.Router) (SubInfo, string) {
	contentRaw := getTrimedFile(p.path)
	content := decodeBase64Safe(string(contentRaw))
	firstLine, others := getFirstLine(content)
	info, ok := parseSubInfo(firstLine)
	if ok {
		content = others
	}
	return info, content
}

func replaceIllegalBase64(content string) string {
	result := content
	result = strings.ReplaceAll(result, "-", "+")
	result = strings.ReplaceAll(result, "_", "/")
	return result
}

func decodeBase64Safe(content string) string {
	reg1 := regexp.MustCompile(`^(?:[A-Za-z0-9-_+/]{4})*[A-Za-z0-9_+/]{4}$`)
	reg2 := regexp.MustCompile(`^(?:[A-Za-z0-9-_+/]{4})*[A-Za-z0-9_+/]{3}(=)?$`)
	reg3 := regexp.MustCompile(`^(?:[A-Za-z0-9-_+/]{4})*[A-Za-z0-9_+/]{2}(==)?$`)
	var result []string
	result = reg1.FindStringSubmatch(content)
	if len(result) > 0 {
		decode, err := base64.StdEncoding.DecodeString(replaceIllegalBase64(content))
		if err == nil {
			return string(decode)
		}
	}
	result = reg2.FindStringSubmatch(content)
	if len(result) > 0 {
		equals := ""
		if result[1] == "" {
			equals = "="
		}
		decode, err := base64.StdEncoding.DecodeString(replaceIllegalBase64(content + equals))
		if err == nil {
			return string(decode)
		}
	}
	result = reg3.FindStringSubmatch(content)
	if len(result) > 0 {
		equals := ""
		if result[1] == "" {
			equals = "=="
		}
		decode, err := base64.StdEncoding.DecodeString(replaceIllegalBase64(content + equals))
		if err == nil {
			return string(decode)
		}
	}
	return content
}

func (p *myProviderAdapter) checkChange(outbounds []option.Outbound) bool {
	if len(p.lastOuts) != len(outbounds) {
		return true
	}
	outMap := make(map[string]option.Outbound, len(p.lastOuts))
	for _, out := range p.lastOuts {
		outMap[out.Tag] = out
	}
	return !common.All(outbounds, func(it option.Outbound) bool {
		out, exits := outMap[it.Tag]
		return exits && reflect.DeepEqual(out, it)
	})
}

func (p *myProviderAdapter) parseOutbounds(ctx context.Context, router adapter.Router, content string) ([]adapter.Outbound, error) {
	outbounds, err := newParser(content, p.overrideDialer)
	if err != nil {
		return nil, err
	}
	finalOuts := common.Filter(outbounds, func(it option.Outbound) bool {
		return O.TestIncludes(it.Tag, p.includes) && O.TestExcludes(it.Tag, p.excludes) && O.TestTypes(it.Type, p.types) && O.TestPorts(it.Port(), p.ports)
	})
	if !p.checkChange(finalOuts) {
		return nil, nil
	}
	p.lastOuts = finalOuts
	return p.createOutbounds(ctx, router, finalOuts)
}

func (p *myProviderAdapter) updateProviderFromContent(ctx context.Context, router adapter.Router, content string) (bool, error) {
	outbounds, err := p.parseOutbounds(ctx, router, decodeBase64Safe(content))
	if err != nil {
		return false, err
	} else if outbounds == nil {
		p.logger.Debug("provider ", p.tag, " has no changes")
		return false, nil
	}

	outbounds, outboundByTag, err := p.startOutbounds(router, outbounds)
	if err != nil {
		return false, err
	}

	outsBackup := p.outbounds
	outByTagBackup := p.outboundByTag
	p.outbounds = outbounds
	p.outboundByTag = outboundByTag

	if err := p.updateGroups(router); err != nil {
		for _, out := range outbounds {
			common.Close(out)
		}
		p.outbounds = outsBackup
		p.outboundByTag = outByTagBackup
		return false, err
	}

	return true, nil
}

func (p *myProviderAdapter) UpdateOutboundByTag() {
	outboundByTag := make(map[string]adapter.Outbound)
	for _, out := range p.outbounds {
		tag := out.Tag()
		outboundByTag[tag] = out
	}
	p.outboundByTag = outboundByTag
}

func (p *myProviderAdapter) startOutbounds(router adapter.Router, outbounds []adapter.Outbound) ([]adapter.Outbound, map[string]adapter.Outbound, error) {
	pTag := p.Tag()
	outboundTag := make(map[string]bool)
	for _, out := range router.Outbounds() {
		outboundTag[out.Tag()] = true
	}
	for _, p := range router.OutboundProviders() {
		if p.Tag() == pTag {
			continue
		}
		for _, out := range p.Outbounds() {
			outboundTag[out.Tag()] = true
		}
	}
	for i, out := range outbounds {
		var tag string
		if out.Tag() == "" {
			tag = fmt.Sprint("[", pTag, "]", F.ToString(i))
		} else {
			tag = out.Tag()
		}
		if _, exists := outboundTag[tag]; exists {
			i := 1
			for {
				tTag := fmt.Sprint(tag, "[", i, "]")
				if _, exists := outboundTag[tTag]; exists {
					i++
					continue
				}
				tag = tTag
				break
			}
			out.SetTag(tag)
		}
		outboundTag[tag] = true
		monitor := taskmonitor.New(p.logger, C.StartTimeout)
		if starter, isStarter := out.(common.Starter); isStarter {
			monitor.Start("initialize outbound provider[", pTag, "]", " outbound/", out.Type(), "[", tag, "]")
			err := starter.Start()
			monitor.Finish()
			if err != nil {
				return nil, nil, E.Cause(err, "initialize outbound provider[", pTag, "]", " outbound/", out.Type(), "[", tag, "]")
			}
		}
	}
	outboundByTag := make(map[string]adapter.Outbound)
	for _, out := range outbounds {
		tag := out.Tag()
		outboundByTag[tag] = out
	}
	return outbounds, outboundByTag, nil
}

func (p *myProviderAdapter) updateGroups(router adapter.Router) error {
	for _, outbound := range router.Outbounds() {
		if group, ok := outbound.(adapter.OutboundGroup); ok {
			p.logger.Debug("update outbound group[", group.Tag(), "] with outbound provider[", p.tag, "]")
			err := group.UpdateOutbounds(p.tag)
			if err != nil {
				return E.Cause(err, "update outbound group[", group.Tag(), "] with outbound provider[", p.tag, "]")
			}
		}
	}
	return nil
}

func (p *myProviderAdapter) refreshURLTestSelected(router adapter.Router) {
	for _, outbound := range router.Outbounds() {
		if group, ok := outbound.(adapter.URLTestGroup); ok {
			group.PerformUpdateCheck(p.tag, false)
		}
	}
}

func (p *myProviderAdapter) CheckOutbounds(force bool) {
	p.healthcheck(p.ctx, p.healthcheckUrl, force)
	p.refreshURLTestSelected(p.router)
}

func (p *myProviderAdapter) Healthcheck(ctx context.Context, link string, force bool) (map[string]uint16, error) {
	url := p.healthcheckUrl
	if link != "" {
		url = link
	}
	return p.healthcheck(ctx, url, force)
}

func (p *myProviderAdapter) healthcheck(ctx context.Context, link string, force bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if p.checking.Swap(true) {
		return result, nil
	}
	defer p.checking.Store(false)

	if !force && time.Since(p.lastHealthcheck) < p.healthcheckInterval {
		return result, nil
	}
	p.lastHealthcheck = time.Now()
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range p.outbounds {
		tag := detour.Tag()
		if checked[tag] {
			continue
		}
		checked[tag] = true
		detour, loaded := p.outboundByTag[tag]
		if !loaded {
			continue
		}
		b.Go(tag, func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), C.TCPTimeout)
			defer cancel()
			t, err := urltest.URLTest(ctx, link, detour)
			if err != nil {
				p.logger.Debug("outbound ", tag, " unavailable: ", err)
				p.healchcheckHistory.DeleteURLTestHistory(tag)
			} else {
				p.logger.Debug("outbound ", tag, " available: ", t, "ms")
				p.healchcheckHistory.StoreURLTestHistory(tag, &urltest.History{
					Time:  time.Now(),
					Delay: t,
				})
				resultAccess.Lock()
				result[tag] = t
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	for _, outbound := range p.router.Outbounds() {
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			continue
		}
		selector, isSeletor := group.(adapter.SelectorGroup)
		if !isSeletor {
			continue
		}
		selector.UpdateSelected(p.tag)
	}
	return result, nil
}

func (p *myProviderAdapter) InterfaceUpdated() {
	p.healthcheck(p.ctx, p.healthcheckUrl, true)
}

func (p *myProviderAdapter) Close() error {
	if p.ticker != nil {
		p.ticker.Stop()
	}
	p.cancel()
	return nil
}
