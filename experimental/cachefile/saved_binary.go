package cachefile

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/hash"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/varbin"
)

// The branch envelope has its own version namespace. Its payload is the
// unchanged upstream SavedBinary wire format, including that format's version.
const (
	branchBinaryMagic        = "\x00reF1nd:SavedBinary\x00"
	branchBinaryVersion byte = 1
)

func marshalBranchBinary(value *adapter.SavedBinary) ([]byte, error) {
	payload, err := value.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString(branchBinaryMagic)
	buffer.WriteByte(branchBinaryVersion)
	_, err = varbin.WriteUvarint(&buffer, uint64(len(payload)))
	if err != nil {
		return nil, err
	}
	buffer.Write(payload)
	buffer.Write(value.Hash.Bytes())
	return buffer.Bytes(), nil
}

func unmarshalBranchBinary(data []byte) (*adapter.SavedBinary, error) {
	if !bytes.HasPrefix(data, []byte(branchBinaryMagic)) {
		return nil, E.New("invalid branch cache magic")
	}
	reader := bytes.NewReader(data[len(branchBinaryMagic):])
	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != branchBinaryVersion {
		return nil, E.New("unsupported branch cache version: ", version)
	}
	length, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, err
	}
	value := new(adapter.SavedBinary)
	if reader.Len() < value.Hash.Len() || length != uint64(reader.Len()-value.Hash.Len()) {
		return nil, E.New("invalid branch cache payload length")
	}
	payload := make([]byte, int(length))
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return nil, err
	}
	// Reject unknown upstream versions independently of the branch version.
	if len(payload) == 0 || (payload[0] != 1 && payload[0] != 2) {
		return nil, E.New("unsupported SavedBinary version")
	}
	err = value.UnmarshalBinary(payload)
	if err != nil {
		return nil, err
	}
	extension := make([]byte, value.Hash.Len())
	_, err = io.ReadFull(reader, extension)
	if err != nil {
		return nil, err
	}
	err = value.Hash.UnmarshalBinary(extension)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (c *CacheFile) loadBranchBinary(kind []byte, tag string, legacy bool) *adapter.SavedBinary {
	var result *adapter.SavedBinary
	err := c.view(func(tx *bbolt.Tx) error {
		if namespace := c.bucket(tx, bucketBranch); namespace != nil {
			if bucket := namespace.Bucket(kind); bucket != nil {
				if data := bucket.Get([]byte(tag)); data != nil {
					var err error
					result, err = unmarshalBranchBinary(data)
					// A corrupt or unsupported new record must not resurrect an old record.
					return err
				}
			}
		}
		if !legacy {
			return os.ErrNotExist
		}
		bucket := c.bucket(tx, kind)
		if bucket == nil {
			return os.ErrNotExist
		}
		data := bucket.Get([]byte(tag))
		if len(data) == 0 || (data[0] != 1 && data[0] != 2) {
			return os.ErrInvalid
		}
		result = new(adapter.SavedBinary)
		if err := result.UnmarshalBinary(data); err != nil {
			return err
		}
		// Legacy records contain the bytes themselves. This also lets the later
		// static-file rule-set loader compare an existing file with its old cache.
		if len(result.Content) > 0 {
			result.Hash = hash.MakeHash(result.Content)
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return result
}

func (c *CacheFile) saveBranchBinary(kind []byte, tag string, value *adapter.SavedBinary) error {
	data, err := marshalBranchBinary(value)
	if err != nil {
		return err
	}
	return c.batch(func(tx *bbolt.Tx) error {
		namespace, err := c.createBucket(tx, bucketBranch)
		if err != nil {
			return err
		}
		bucket, err := namespace.CreateBucketIfNotExists(kind)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(tag), data)
	})
}
