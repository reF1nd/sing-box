package sniff

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"io"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff/internal/qtls"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/crypto/hkdf"
)

func QUICClientHello(ctx context.Context, packet []byte, sniffdata chan SniffData) {
	reader := bytes.NewReader(packet)
	data := SniffData{
		metadata: nil,
		err:      nil,
	}
	defer func() {
		sniffdata <- data
	}()
	typeByte, err := reader.ReadByte()
	if err != nil {
		data.err = err
		return
	}
	if typeByte&0x40 == 0 {
		data.err = E.New("bad type byte")
		return
	}
	var versionNumber uint32
	err = binary.Read(reader, binary.BigEndian, &versionNumber)
	if err != nil {
		data.err = err
		return
	}
	if versionNumber != qtls.VersionDraft29 && versionNumber != qtls.Version1 && versionNumber != qtls.Version2 {
		data.err = E.New("bad version")
		return
	}
	packetType := (typeByte & 0x30) >> 4
	if packetType == 0 && versionNumber == qtls.Version2 || packetType == 2 && versionNumber != qtls.Version2 || packetType > 2 {
		data.err = E.New("bad packet type")
		return
	}

	destConnIDLen, err := reader.ReadByte()
	if err != nil {
		data.err = err
		return
	}

	if destConnIDLen == 0 || destConnIDLen > 20 {
		data.err = E.New("bad destination connection id length")
		return
	}

	destConnID := make([]byte, destConnIDLen)
	_, err = io.ReadFull(reader, destConnID)
	if err != nil {
		data.err = err
		return
	}

	srcConnIDLen, err := reader.ReadByte()
	if err != nil {
		data.err = err
		return
	}

	_, err = io.CopyN(io.Discard, reader, int64(srcConnIDLen))
	if err != nil {
		data.err = err
		return
	}

	tokenLen, err := qtls.ReadUvarint(reader)
	if err != nil {
		data.err = err
		return
	}

	_, err = io.CopyN(io.Discard, reader, int64(tokenLen))
	if err != nil {
		data.err = err
		return
	}

	packetLen, err := qtls.ReadUvarint(reader)
	if err != nil {
		data.err = err
		return
	}

	hdrLen := int(reader.Size()) - reader.Len()
	if hdrLen+int(packetLen) > len(packet) {
		data.err = os.ErrInvalid
		return
	}

	_, err = io.CopyN(io.Discard, reader, 4)
	if err != nil {
		data.err = err
		return
	}

	pnBytes := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(reader, pnBytes)
	if err != nil {
		data.err = err
		return
	}

	var salt []byte
	switch versionNumber {
	case qtls.Version1:
		salt = qtls.SaltV1
	case qtls.Version2:
		salt = qtls.SaltV2
	default:
		salt = qtls.SaltOld
	}
	var hkdfHeaderProtectionLabel string
	switch versionNumber {
	case qtls.Version2:
		hkdfHeaderProtectionLabel = qtls.HKDFLabelHeaderProtectionV2
	default:
		hkdfHeaderProtectionLabel = qtls.HKDFLabelHeaderProtectionV1
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
	secret := qtls.HKDFExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	hpKey := qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, hkdfHeaderProtectionLabel, 16)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		data.err = err
		return
	}
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, pnBytes)
	newPacket := make([]byte, len(packet))
	copy(newPacket, packet)
	newPacket[0] ^= mask[0] & 0xf
	for i := range newPacket[hdrLen : hdrLen+4] {
		newPacket[hdrLen+i] ^= mask[i+1]
	}
	packetNumberLength := newPacket[0]&0x3 + 1
	if hdrLen+int(packetNumberLength) > int(packetLen)+hdrLen {
		data.err = os.ErrInvalid
		return
	}
	var packetNumber uint32
	switch packetNumberLength {
	case 1:
		packetNumber = uint32(newPacket[hdrLen])
	case 2:
		packetNumber = uint32(binary.BigEndian.Uint16(newPacket[hdrLen:]))
	case 3:
		packetNumber = uint32(newPacket[hdrLen+2]) | uint32(newPacket[hdrLen+1])<<8 | uint32(newPacket[hdrLen])<<16
	case 4:
		packetNumber = binary.BigEndian.Uint32(newPacket[hdrLen:])
	default:
		data.err = E.New("bad packet number length")
		return
	}
	extHdrLen := hdrLen + int(packetNumberLength)
	copy(newPacket[extHdrLen:hdrLen+4], packet[extHdrLen:])
	pdata := newPacket[extHdrLen : int(packetLen)+hdrLen]

	var keyLabel string
	var ivLabel string
	switch versionNumber {
	case qtls.Version2:
		keyLabel = qtls.HKDFLabelKeyV2
		ivLabel = qtls.HKDFLabelIVV2
	default:
		keyLabel = qtls.HKDFLabelKeyV1
		ivLabel = qtls.HKDFLabelIVV1
	}

	key := qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, keyLabel, 16)
	iv := qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, ivLabel, 12)
	cipher := qtls.AEADAESGCMTLS13(key, iv)
	nonce := make([]byte, int32(cipher.NonceSize()))
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(packetNumber))
	decrypted, err := cipher.Open(newPacket[extHdrLen:extHdrLen], nonce, pdata, newPacket[:extHdrLen])
	if err != nil {
		data.err = err
		return
	}
	var frameType byte
	var frameLen uint64
	var fragments []struct {
		offset  uint64
		length  uint64
		payload []byte
	}
	decryptedReader := bytes.NewReader(decrypted)
	for {
		frameType, err = decryptedReader.ReadByte()
		if err == io.EOF {
			break
		}
		switch frameType {
		case 0x00: // PADDING
			continue
		case 0x01: // PING
			continue
		case 0x02, 0x03: // ACK
			_, err = qtls.ReadUvarint(decryptedReader) // Largest Acknowledged
			if err != nil {
				data.err = err
				return
			}
			_, err = qtls.ReadUvarint(decryptedReader) // ACK Delay
			if err != nil {
				data.err = err
				return
			}
			ackRangeCount, err := qtls.ReadUvarint(decryptedReader) // ACK Range Count
			if err != nil {
				data.err = err
				return
			}
			_, err = qtls.ReadUvarint(decryptedReader) // First ACK Range
			if err != nil {
				data.err = err
				return
			}
			for i := 0; i < int(ackRangeCount); i++ {
				_, err = qtls.ReadUvarint(decryptedReader) // Gap
				if err != nil {
					data.err = err
					return
				}
				_, err = qtls.ReadUvarint(decryptedReader) // ACK Range Length
				if err != nil {
					data.err = err
					return
				}
			}
			if frameType == 0x03 {
				_, err = qtls.ReadUvarint(decryptedReader) // ECT0 Count
				if err != nil {
					data.err = err
					return
				}
				_, err = qtls.ReadUvarint(decryptedReader) // ECT1 Count
				if err != nil {
					data.err = err
					return
				}
				_, err = qtls.ReadUvarint(decryptedReader) // ECN-CE Count
				if err != nil {
					data.err = err
					return
				}
			}
		case 0x06: // CRYPTO
			var offset uint64
			offset, err = qtls.ReadUvarint(decryptedReader)
			if err != nil {
				data.metadata = &adapter.InboundContext{Protocol: C.ProtocolQUIC}
				data.err = err
				return
			}
			var length uint64
			length, err = qtls.ReadUvarint(decryptedReader)
			if err != nil {
				data.metadata = &adapter.InboundContext{Protocol: C.ProtocolQUIC}
				data.err = err
				return
			}
			index := len(decrypted) - decryptedReader.Len()
			fragments = append(fragments, struct {
				offset  uint64
				length  uint64
				payload []byte
			}{offset, length, decrypted[index : index+int(length)]})
			frameLen += length
			_, err = decryptedReader.Seek(int64(length), io.SeekCurrent)
			if err != nil {
				data.err = err
				return
			}
		case 0x1c: // CONNECTION_CLOSE
			_, err = qtls.ReadUvarint(decryptedReader) // Error Code
			if err != nil {
				data.err = err
				return
			}
			_, err = qtls.ReadUvarint(decryptedReader) // Frame Type
			if err != nil {
				data.err = err
				return
			}
			var length uint64
			length, err = qtls.ReadUvarint(decryptedReader) // Reason Phrase Length
			if err != nil {
				data.err = err
				return
			}
			_, err = decryptedReader.Seek(int64(length), io.SeekCurrent) // Reason Phrase
			if err != nil {
				data.err = err
				return
			}
		default:
			data.err = os.ErrInvalid
			return
		}
	}
	tlsHdr := make([]byte, 5)
	tlsHdr[0] = 0x16
	binary.BigEndian.PutUint16(tlsHdr[1:], uint16(0x0303))
	binary.BigEndian.PutUint16(tlsHdr[3:], uint16(frameLen))
	var index uint64
	var length int
	var readers []io.Reader
	readers = append(readers, bytes.NewReader(tlsHdr))
find:
	for {
		for _, fragment := range fragments {
			if fragment.offset == index {
				readers = append(readers, bytes.NewReader(fragment.payload))
				index = fragment.offset + fragment.length
				length++
				continue find
			}
		}
		if length == len(fragments) {
			break
		}
		data.metadata = &adapter.InboundContext{Protocol: C.ProtocolQUIC}
		data.err = E.New("bad fragments")
		return
	}
	tlsdatachan := make(chan SniffData, 1)
	TLSClientHello(ctx, io.MultiReader(readers...), tlsdatachan)
	tlsdata := <-tlsdatachan
	metadata := tlsdata.metadata
	err = tlsdata.err
	if err != nil {
		data.metadata = &adapter.InboundContext{Protocol: C.ProtocolQUIC}
		data.err = err
		return
	}
	metadata.Protocol = C.ProtocolQUIC
	data.metadata = metadata
	data.err = nil
}
