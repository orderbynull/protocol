package pgsql

import (
	"bytes"
	"encoding/binary"
	"github.com/orderbynull/protocol"
	"io"
)

const (
	fieldSeverity1 = 0x53 //S
	fieldSeverity2 = 0x56 //V
	fieldCode      = 0x34 //C
	fieldMessage   = 0x4d //M
)

type BaseMessage struct {
	Options map[string]string
}

type ParseMessage struct {
	BaseMessage
	Query string
}

func (p *ParseMessage) decode(data []byte) {
	r := bytes.NewReader(data)

	// Skip packet header
	if _, err := r.Seek(5, io.SeekStart); err != nil {
		return
	}

	protocol.SkipNullTerminatedString(r)
	p.Query = protocol.ReadNullTerminatedString(r)
}

func (p *ParseMessage) String() string {
	return p.Query
}

type ErrorMessage struct {
	BaseMessage
	Message string
}

func (e *ErrorMessage) decode(data []byte) {
	r := bytes.NewReader(data)

	// Skip packet header
	if _, err := r.Seek(5, io.SeekStart); err != nil {
		return
	}

	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			return
		}
		if err != nil {
			println(err)
		}
		switch b {
		case fieldMessage:
			e.Message = protocol.ReadNullTerminatedString(r)
		default:
			protocol.SkipNullTerminatedString(r)
		}
	}
}

func (e *ErrorMessage) String() string {
	return e.Message
}

type PacketBuilder struct {
	buf bytes.Buffer
}

// Build ...
func (p *PacketBuilder) Build(b []byte) (*Packet, error) {
	if _, err := p.buf.Write(b); err != nil {
		return nil, err
	}
	if isValidPacket(p.buf.Bytes()) {
		packet := &Packet{p.buf.Bytes()}
		p.buf.Reset()
		return packet, nil
	}

	return nil, nil
}

type Packet struct {
	Payload []byte
}

func (p *Packet) Messages() []interface{} {
	if isStartupMessage(p.Payload) || isSSLRequestMessage(p.Payload) || isCancelRequestMessage(p.Payload) {
		return nil
	}

	var offset uint32
	var messages []interface{}
	for {
		if len(p.Payload[offset:]) < 5 {
			break
		}

		pktLen := binary.BigEndian.Uint32(p.Payload[offset+1:offset+5]) + 1
		packet := p.Payload[offset : offset+pktLen]
		offset = offset + pktLen

		if isParseMessage(packet) {
			pm := ParseMessage{}
			pm.decode(packet)
			messages = append(messages, pm)
			continue
		}
		//if isErrorMessage(packet) {
		//	em := ErrorMessage{}
		//	em.decode(packet)
		//	messages = append(messages, em)
		//	continue
		//}
	}

	return messages
}

func isErrorMessage(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0] != 0x45 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[1:5]) + 1
	return pktLen == uint32(len(data))
}

// isParseMessage возвращает true если пакет является Parse.
func isParseMessage(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	if data[0] != 0x50 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[1:5]) + 1
	return pktLen == uint32(len(data))
}

// isCancelRequest возвращает true если пакет является CancelRequest.
// CancelRequest не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета, которая всегда равна 16.
// Вторые 4 байта содержат код пакета, который всегда равен 80877102.
// Остальные 8 байт не представляют интереса для валидации пакета.
// Источник сообщения - клиент.
func isCancelRequestMessage(data []byte) bool {
	if len(data) != 16 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[0:4])
	if pktLen != 16 {
		return false
	}
	requestCode := binary.BigEndian.Uint32(data[4:8])
	return requestCode == 80877102
}

// isSSLRequest возвращает true если пакет является SSLRequest.
// SSLRequest не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета, которая всегда равна 8.
// Вторые 4 байта содержат код пакета, который всегда равен 80877103.
// Источник сообщения - клиент.
func isSSLRequestMessage(data []byte) bool {
	if len(data) != 8 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[0:4])
	if pktLen != 8 {
		return false
	}
	requestCode := binary.BigEndian.Uint32(data[4:8])
	return requestCode == 80877103
}

// isStartupMessage возвращает true если пакет является StartupMessage.
// StartupMessage не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета.
// Вторые 4 байта содержат версию протокола, которая всегда равна 196608.
// Источник сообщения - клиент.
func isStartupMessage(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(data[0:4])
	if pktLen != uint32(len(data)) {
		return false
	}
	protoVer := binary.BigEndian.Uint32(data[4:8])
	return protoVer == 196608 //v3.0
}

func isNoOpMessage(data []byte) bool {
	return len(data) == 1
}

// isValidPacket возвращает true если data это валидный пакет.
// Учитывается, что data может состоять как из одного пакета, так и из множества пакетов.
// В последнем случае data валиден если каждый пакет из data валиден.
func isValidPacket(data []byte) bool {
	if isNoOpMessage(data) {
		return true
	}

	if len(data) < 5 {
		return false
	}

	// Эти типы сообщений в заголовке не содержат байт типа пакета, поэтому их нужно обработать сразу
	if isStartupMessage(data) || isSSLRequestMessage(data) || isCancelRequestMessage(data) {
		return true
	}

	var offset uint32
	for {
		// Если длина остатка пакета меньше пяти, то это однозначно неверный пакет.
		// Минимальный пакет состоит из типа пакета(1 байт) и длины пакета(4 байта).
		if len(data[offset:]) < 5 {
			break
		}
		pktLen := binary.BigEndian.Uint32(data[offset+1:offset+5]) + 1
		// Если ожидаемая длина остатка пакета совпадает с фактической длиной остатка пакета,
		// то либо Payload это всего один пакет и он валидный, либо цикл дошел уже до последнего пакета в Payload и
		// это автоматически значит, что все пакеты в Payload так же валидны.
		if pktLen == uint32(len(data[offset:])) {
			return true
		}
		// Ожидаемая длина пакета не может быть больше фактической длины пакета.
		if pktLen > uint32(len(data[offset:])) {
			break
		}
		offset = offset + pktLen
	}
	return false
}
