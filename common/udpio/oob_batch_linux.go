//go:build linux

package udpio

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

type mmsghdr struct {
	msgHdr unix.Msghdr
	msgLen uint32
}

type oobPacketBatchReadWaiter struct {
	rawConn  syscall.RawConn
	readErr  error
	readN    int
	oobSize  int
	readFunc func(fd uintptr) bool
	buffers  []*buf.Buffer
	oobs     [][]byte
	control  [][]byte
	sources  []M.Socksaddr
	names    []unix.RawSockaddrAny
	iovecs   []unix.Iovec
	messages []mmsghdr
	options  N.ReadWaitOptions
}

func newOOBPacketBatchReadWaiter(conn *net.UDPConn, oobSize int) (OOBPacketBatchReadWaiter, bool) {
	if conn == nil || oobSize <= 0 {
		return nil, false
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, false
	}
	return &oobPacketBatchReadWaiter{rawConn: rawConn, oobSize: oobSize}, true
}

func (w *oobPacketBatchReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	w.releaseBuffers()
	if options.BatchSize <= 0 {
		options.BatchSize = 1
	}
	w.options = options
	w.buffers = make([]*buf.Buffer, options.BatchSize)
	w.oobs = make([][]byte, options.BatchSize)
	w.control = make([][]byte, options.BatchSize)
	w.sources = make([]M.Socksaddr, options.BatchSize)
	w.names = make([]unix.RawSockaddrAny, options.BatchSize)
	w.iovecs = make([]unix.Iovec, options.BatchSize)
	w.messages = make([]mmsghdr, options.BatchSize)
	for index := range w.control {
		w.control[index] = make([]byte, w.oobSize)
	}
	w.readFunc = func(fd uintptr) bool {
		for index := range w.messages {
			buffer := w.buffers[index]
			if buffer == nil {
				buffer = w.options.NewPacketBuffer()
				w.buffers[index] = buffer
			}
			w.names[index] = unix.RawSockaddrAny{}
			w.iovecs[index] = buffer.Iovec(buffer.FreeLen())
			w.messages[index] = mmsghdr{}
			w.messages[index].msgHdr.Name = (*byte)(unsafe.Pointer(&w.names[index]))
			w.messages[index].msgHdr.Namelen = unix.SizeofSockaddrAny
			w.messages[index].msgHdr.Iov = &w.iovecs[index]
			w.messages[index].msgHdr.SetIovlen(1)
			w.oobs[index] = nil
			w.messages[index].msgHdr.Control = &w.control[index][0]
			w.messages[index].msgHdr.SetControllen(len(w.control[index]))
		}
		for {
			var errno syscall.Errno
			w.readN, errno = recvmmsg(int(fd), w.messages, 0)
			switch errno {
			case 0:
				w.readErr = nil
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				w.releaseBuffers()
				return false
			default:
				if errno == syscall.EWOULDBLOCK {
					w.releaseBuffers()
					return false
				}
				w.readErr = os.NewSyscallError("recvmmsg", errno)
			}
			break
		}
		if w.readN == 0 && w.readErr == nil {
			w.readErr = io.EOF
		}
		for index := 0; index < w.readN; index++ {
			message := &w.messages[index]
			if message.msgHdr.Flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
				w.readErr = errors.New("packet payload or ancillary data was truncated")
				break
			}
			buffer := w.buffers[index]
			buffer.Truncate(int(message.msgLen))
			w.options.PostReturn(buffer)
			oobLen := min(int(message.msgHdr.Controllen), len(w.control[index]))
			w.oobs[index] = w.control[index][:oobLen]
			w.sources[index] = M.SocksaddrFromRawSockaddrAny(&w.names[index])
		}
		return true
	}
	return false
}

func (w *oobPacketBatchReadWaiter) WaitReadOOBPackets() (buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr, err error) {
	if w.readFunc == nil {
		return nil, nil, nil, os.ErrInvalid
	}
	defer w.releaseBuffers()
	err = w.rawConn.Read(w.readFunc)
	if err != nil {
		return
	}
	if w.readErr != nil {
		if w.readErr == io.EOF {
			return nil, nil, nil, io.EOF
		}
		return nil, nil, nil, E.Cause(w.readErr, "raw read")
	}
	buffers = make([]*buf.Buffer, w.readN)
	sources = make([]M.Socksaddr, w.readN)
	for index := 0; index < w.readN; index++ {
		buffers[index] = w.buffers[index]
		w.buffers[index] = nil
		sources[index] = w.sources[index]
	}
	oobs = w.oobs[:w.readN]
	w.readN = 0
	return
}

func (w *oobPacketBatchReadWaiter) releaseBuffers() {
	clear(w.iovecs)
	clear(w.messages)
	buf.ReleaseMulti(w.buffers)
	clear(w.buffers)
	w.readN = 0
}

type oobPacketBatchWriter struct {
	rawConn  syscall.RawConn
	ipv6     bool
	access   sync.Mutex
	names    []unix.RawSockaddrAny
	iovecs   []unix.Iovec
	messages []mmsghdr
}

func newOOBPacketBatchWriter(conn *net.UDPConn, ipv6 bool) (OOBPacketBatchWriter, bool) {
	if conn == nil {
		return nil, false
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, false
	}
	return &oobPacketBatchWriter{rawConn: rawConn, ipv6: ipv6}, true
}

func (w *oobPacketBatchWriter) WriteOOBPacketBatch(buffers []*buf.Buffer, oobs [][]byte, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(oobs) || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	w.access.Lock()
	defer w.access.Unlock()
	defer buf.ReleaseMulti(buffers)
	w.names = growSlice(w.names, len(buffers))
	w.iovecs = growSlice(w.iovecs, len(buffers))
	w.messages = growSlice(w.messages, len(buffers))
	defer func() {
		clear(w.iovecs)
		clear(w.messages)
		w.names = w.names[:0]
		w.iovecs = w.iovecs[:0]
		w.messages = w.messages[:0]
	}()
	for index, buffer := range buffers {
		w.names[index] = unix.RawSockaddrAny{}
		w.iovecs[index] = unix.Iovec{}
		w.messages[index] = mmsghdr{}
		w.messages[index].msgHdr.Name = (*byte)(unsafe.Pointer(&w.names[index]))
		w.messages[index].msgHdr.Namelen = M.AddrPortToRawSockaddrAny(
			&w.names[index],
			destinations[index].AddrPort(),
			w.ipv6,
		)
		if !buffer.IsEmpty() {
			w.iovecs[index] = buffer.Iovec(buffer.Len())
			w.messages[index].msgHdr.Iov = &w.iovecs[index]
			w.messages[index].msgHdr.SetIovlen(1)
		}
		if len(oobs[index]) > 0 {
			w.messages[index].msgHdr.Control = &oobs[index][0]
			w.messages[index].msgHdr.SetControllen(len(oobs[index]))
		}
	}
	pending := w.messages
	var syscallErr syscall.Errno
	err := w.rawConn.Write(func(fd uintptr) bool {
		for len(pending) > 0 {
			written, errno := sendmmsg(int(fd), pending, 0)
			switch errno {
			case 0:
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				return false
			default:
				if errno == syscall.EWOULDBLOCK {
					return false
				}
				syscallErr = errno
				return true
			}
			if written == 0 {
				syscallErr = syscall.EIO
				return true
			}
			pending = pending[written:]
		}
		return true
	})
	runtime.KeepAlive(buffers)
	runtime.KeepAlive(oobs)
	runtime.KeepAlive(destinations)
	if syscallErr != 0 {
		return os.NewSyscallError("sendmmsg", syscallErr)
	}
	return err
}

func growSlice[T any](values []T, size int) []T {
	if cap(values) < size {
		return make([]T, size)
	}
	return values[:size]
}

func recvmmsg(fd int, messages []mmsghdr, flags int) (int, syscall.Errno) {
	return mmsgSyscall(unix.SYS_RECVMMSG, fd, messages, flags)
}

func sendmmsg(fd int, messages []mmsghdr, flags int) (int, syscall.Errno) {
	return mmsgSyscall(unix.SYS_SENDMMSG, fd, messages, flags)
}

func mmsgSyscall(trap uintptr, fd int, messages []mmsghdr, flags int) (int, syscall.Errno) {
	result, _, errno := unix.Syscall6(
		trap,
		uintptr(fd),
		uintptr(unsafe.Pointer(&messages[0])),
		uintptr(len(messages)),
		uintptr(flags),
		0,
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(result), 0
}
