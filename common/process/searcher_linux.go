//go:build linux

package process

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	pathProc = "/proc"

	processPathsAllUsers = ^uint32(0)
)

var _ Searcher = (*linuxSearcher)(nil)

type linuxSearcher struct {
	logger           log.ContextLogger
	packageManager   tun.PackageManager
	diagConns        [4]*socketDiagConn
	processPathCache *processPathCache
}

func NewSearcher(config Config) (Searcher, error) {
	searcher := &linuxSearcher{
		logger:           config.Logger,
		packageManager:   config.PackageManager,
		processPathCache: newProcessPathCache(buildProcessPaths),
	}
	for _, family := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		for _, protocol := range []uint8{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			searcher.diagConns[socketDiagConnIndex(family, protocol)] = &socketDiagConn{
				family:   family,
				protocol: protocol,
				fd:       -1,
			}
		}
	}
	return searcher, nil
}

func (s *linuxSearcher) ResetCache() {
	s.processPathCache.reset()
}

func (s *linuxSearcher) Close() error {
	s.processPathCache.close()
	var errs []error
	for _, conn := range s.diagConns {
		if conn == nil {
			continue
		}
		errs = append(errs, conn.Close())
	}
	return E.Errors(errs...)
}

func (s *linuxSearcher) FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	return s.FindProcessInfoMode(ctx, network, source, destination, LookupFull)
}

func (s *linuxSearcher) FindProcessInfoMode(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort, mode LookupMode) (*adapter.ConnectionOwner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inode, uid, err := s.resolveSocketByNetlink(network, source, destination)
	if err != nil {
		return nil, err
	}
	processInfo := &adapter.ConnectionOwner{
		UserId: int32(uid),
	}
	completeProcessInfo(processInfo, s.packageManager)
	if mode == LookupOwner && len(processInfo.AndroidPackageNames) > 0 {
		processInfo.ProcessPath = s.processPathCache.cached(inode, uid)
		return processInfo, nil
	}
	processPath, err := s.processPathCache.find(ctx, inode, uid, mode == LookupFull)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		s.logger.DebugContext(ctx, "find process path: ", err)
	} else {
		processInfo.ProcessPath = processPath
	}
	return processInfo, nil
}

// FindProcessInfoByPID resolves process metadata without scanning socket file
// descriptors across procfs. The caller already established socket ownership.
func FindProcessInfoByPID(processID uint32, userID uint32, packageManager tun.PackageManager) (*adapter.ConnectionOwner, error) {
	processInfo := &adapter.ConnectionOwner{
		ProcessID: processID,
		UserId:    int32(userID),
	}
	processPath, err := os.Readlink(filepath.Join(pathProc, strconv.FormatUint(uint64(processID), 10), "exe"))
	if err == nil {
		processInfo.ProcessPath = processPath
	}
	completeProcessInfo(processInfo, packageManager)
	return processInfo, err
}

func (s *linuxSearcher) resolveSocketByNetlink(network string, source netip.AddrPort, destination netip.AddrPort) (inode, uid uint32, err error) {
	source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	family, protocol, err := socketDiagSettings(network, source)
	if err != nil {
		return 0, 0, err
	}
	conn := s.diagConns[socketDiagConnIndex(family, protocol)]
	if conn == nil {
		return 0, 0, E.New("missing socket diag connection for family=", family, " protocol=", protocol)
	}
	if destination.IsValid() && source.Addr().BitLen() == destination.Addr().BitLen() {
		inode, uid, err = conn.query(source, destination)
		if err == nil {
			return inode, uid, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return 0, 0, err
		}
	}
	return dumpSocketDiag(family, protocol, source, destination)
}

func buildProcessPaths(ctx context.Context, uid uint32) (map[uint32]string, error) {
	files, err := os.ReadDir(pathProc)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, syscall.PathMax)
	processPaths := make(map[uint32]string)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !file.IsDir() || !isPid(file.Name()) {
			continue
		}
		info, err := file.Info()
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, err
		}
		if uid != processPathsAllUsers && info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}
		processPath := filepath.Join(pathProc, file.Name())
		fdPath := filepath.Join(processPath, "fd")
		exePath, err := os.Readlink(filepath.Join(processPath, "exe"))
		if err != nil {
			if isIgnorableProcError(err) {
				continue
			}
			return nil, err
		}
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			n, err := syscall.Readlink(filepath.Join(fdPath, fd.Name()), buffer)
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(buffer[:n])
			if !ok {
				continue
			}
			if _, loaded := processPaths[inode]; !loaded {
				processPaths[inode] = exePath
			}
		}
	}
	return processPaths, nil
}

func isIgnorableProcError(err error) bool {
	return os.IsNotExist(err) || os.IsPermission(err)
}

func parseSocketInode(link []byte) (uint32, bool) {
	const socketPrefix = "socket:["
	if len(link) <= len(socketPrefix) || string(link[:len(socketPrefix)]) != socketPrefix || link[len(link)-1] != ']' {
		return 0, false
	}
	var inode uint64
	for _, char := range link[len(socketPrefix) : len(link)-1] {
		if char < '0' || char > '9' {
			return 0, false
		}
		inode = inode*10 + uint64(char-'0')
		if inode > uint64(^uint32(0)) {
			return 0, false
		}
	}
	return uint32(inode), true
}

func isPid(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsDigit(r)
	}) == -1
}
