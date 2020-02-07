package pgsql

import (
	"bytes"
	"encoding/binary"
)

type protocol struct {
	major, minor byte
}

type StartupMessage struct {
	user           string
	database       string
	timeZone       string
	dateStyle      string
	clientEncoding string
	protocol
}

type Packet struct {
	payload    bytes.Buffer
	assembling bool
}

func (p *Packet) appendPayload(b []byte) *Packet {
	p.payload.Write(b)
	return p
}

// Assemble ...
func (p *Packet) Assemble(b []byte) bool {
	return p.appendPayload(b).isValidPacket()
}

func (p *Packet) Decoded() interface{} {
	return nil
}

// isCancelRequest возвращает true если пакет является CancelRequest.
// CancelRequest не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета, которая всегда равна 16.
// Вторые 4 байта содержат код пакета, который всегда равен 80877102.
// Остальные 8 байт не представляют интереса для валидации пакета.
// Источник сообщения - клиент.
func (p *Packet) isCancelRequest() bool {
	payload := p.payload.Bytes()
	if len(payload) != 16 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(payload[0:4])
	if pktLen != 16 {
		return false
	}
	requestCode := binary.BigEndian.Uint32(payload[4:8])
	return requestCode == 80877102
}

// isSSLRequest возвращает true если пакет является SSLRequest.
// SSLRequest не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета, которая всегда равна 8.
// Вторые 4 байта содержат код пакета, который всегда равен 80877103.
// Источник сообщения - клиент.
func (p *Packet) isSSLRequest() bool {
	payload := p.payload.Bytes()
	if len(payload) != 8 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(payload[0:4])
	if pktLen != 8 {
		return false
	}
	requestCode := binary.BigEndian.Uint32(payload[4:8])
	return requestCode == 80877103
}

// isStartupMessage возвращает true если пакет является StartupMessage.
// StartupMessage не содержит тип пакета в заголовке.
// Первые 4 байта содержат длину пакета.
// Вторые 4 байта содержат версию протокола, которая всегда равна 196608.
// Источник сообщения - клиент.
func (p *Packet) isStartupMessage() bool {
	payload := p.payload.Bytes()
	if len(payload) < 8 {
		return false
	}
	pktLen := binary.BigEndian.Uint32(payload[0:4])
	if pktLen != uint32(len(payload)) {
		return false
	}
	protoVer := binary.BigEndian.Uint32(payload[4:8])
	return protoVer == 196608 //v3.0
}

func (p *Packet) isNoOpMessage() bool {
	return len(p.payload.Bytes()) == 1
}

// isValidPacket возвращает true если p.payload это валидный пакет.
// Учитывается, что p.payload может состоять как из одного пакета, так и из множества пакетов.
// В последнем случае p.payload валиден если каждый пакет из data валиден.
func (p *Packet) isValidPacket() bool {
	payload := p.payload.Bytes()
	if len(payload) < 5 {
		return false
	}
	if p.isNoOpMessage() || p.isStartupMessage() || p.isSSLRequest() || p.isCancelRequest() {
		return true
	}

	var offset uint32
	for {
		// Если длина остатка пакета меньше пяти, то это однозначно неверный пакет.
		// Минимальный пакет состоит из типа пакета(1 байт) и длины пакета(4 байта).
		if len(payload[offset:]) < 5 {
			break
		}
		pktLen := binary.BigEndian.Uint32(payload[offset+1:offset+5]) + 1
		// Если ожидаемая длина остатка пакета совпадает с фактической длиной остатка пакета,
		// то либо payload это всего один пакет и он валидный, либо цикл дошел уже до последнего пакета в payload и
		// это автоматически значит, что все пакеты в payload так же валидны.
		if pktLen == uint32(len(payload[offset:])) {
			return true
		}
		// Ожидаемая длина пакета не может быть больше фактической длины пакета.
		if pktLen > uint32(len(payload[offset:])) {
			break
		}
		offset = offset + pktLen
	}
	return false
}
