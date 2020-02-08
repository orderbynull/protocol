package protocol

import "bytes"

func ReadNullTerminatedString(data []byte) string {
	r := bytes.NewReader(data)
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
