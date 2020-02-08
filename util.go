package protocol

import (
	"bytes"
)

func ReadNullTerminatedString(r *bytes.Reader) string {
	var str []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return ""
		}

		if b == 0x00 {
			return string(str)
		} else {
			str = append(str, b)
		}
	}
}
