package pgsql

import (
	"encoding/hex"
	"testing"
)

func decodeHexStream(t *testing.T, stream string) []byte {
	decoded, err := hex.DecodeString(stream)
	if err != nil {
		t.Fatalf("Failed to decode stream in %s", err)
	}
	return decoded
}

func Test_IsCancelRequest_Valid_Packet(t *testing.T) {

}

func Test_IsCancelRequest_InValid_Packet(t *testing.T) {

}

func Test_isSSLRequest_With_ValidPacket_Returns_True(t *testing.T) {
	packet := Packet{decodeHexStream(t, "0000000804d2162f")}
	if !isSSLRequestMessage(packet.payload) {
		t.Error("isSSLRequest expected to return 'true', but 'false' returned")
	}
}

func Test_isSSLRequest_With_InvalidPacket_Returns_False(t *testing.T) {
	invalidPackets := []string{
		"",
		// любые 8 байт, чтобы прошла проверка на длину пакета
		"0000000f0f0f0f00",
		// ожидаемая длина пакета, которая не совпадает с фактической длиной
		"00000070",
		// верный пакет за исключением второй четверки байт(код пакета)
		"000000080fd2162f",
	}
	for _, invalidPacket := range invalidPackets {
		packet := Packet{decodeHexStream(t, invalidPacket)}
		if isSSLRequestMessage(packet.payload) {
			t.Error("isStartupMessage expected to return 'false', but 'true' returned")
		}
	}
}

func Test_isStartupMessage_With_ValidPacket_Returns_True(t *testing.T) {
	packet := Packet{decodeHexStream(t, "0000007000030000757365720079615f74657374696e6700646174616261736500706f73746772657300636c69656e745f656e636f64696e67005554463800446174655374796c650049534f0054696d655a6f6e65005554430065787472615f666c6f61745f64696769747300320000")}
	if !isStartupMessage(packet.payload) {
		t.Error("isStartupMessage expected to return 'true', but 'false' returned")
	}
}

func Test_isStartupMessage_With_InvalidPacket_Returns_False(t *testing.T) {
	invalidPackets := []string{
		"",
		// любые 8 байт, чтобы прошла проверка на длину пакета
		"0000000f0f0f0f00",
		// ожидаемая длина пакета, которая не совпадает с фактической длиной
		"00000070",
		// верный пакет за исключением второй четверки байт(версия протокола)
		"0000007001030000757365720079615f74657374696e6700646174616261736500706f73746772657300636c69656e745f656e636f64696e67005554463800446174655374796c650049534f0054696d655a6f6e65005554430065787472615f666c6f61745f64696769747300320000",
	}
	for _, invalidPacket := range invalidPackets {
		packet := Packet{decodeHexStream(t, invalidPacket)}
		if isStartupMessage(packet.payload) {
			t.Error("isStartupMessage expected to return 'false', but 'true' returned")
		}
	}
}

func Test_isValidPacket_With_ValidPacket_Return_True(t *testing.T) {
	packet := Packet{decodeHexStream(t, "52000000080000000053000000166170706c69636174696f6e5f6e616d6500005300000019636c69656e745f656e636f64696e670055544638005300000017446174655374796c650049534f2c204d4459005300000019696e74656765725f6461746574696d6573006f6e00530000001b496e74657276616c5374796c6500706f73746772657300530000001569735f737570657275736572006f66660053000000197365727665725f656e636f64696e67005554463800530000001a7365727665725f76657273696f6e00392e362e313000530000002573657373696f6e5f617574686f72697a6174696f6e0079615f74657374696e670053000000237374616e646172645f636f6e666f726d696e675f737472696e6773006f6e00530000001154696d655a6f6e6500555443004b0000000c00000bbe3d082f545a0000000549")}
	if !isValidPacket(packet.payload) {
		t.Error("isStartupMessage expected to return 'true', but 'false' returned")
	}
}

func Test_Assemble_With_ValidPacketChunks_Returns_Nil(t *testing.T) {
	chunks := []string{"52000000080000000053000000166170","706c69636174696f6e5f6e616d6500005300000019636c69656e745f656e636f64696e670055544638005300000017446174655374796c650049534f2c204d4459005300000019696e74656765725f6461746574696d6573006f6e00530000001b496e74657276616c5374796c6500706f73746772657300530000001569735f737570657275736572006f66660053000000197365727665725f656e636f64696e67005554463800530000001a7365727665725f76657273696f6e00392e362e313000530000002573657373696f6e5f617574686f72697a6174696f6e0079615f74657374696e670053000000237374616e646172645f636f6e666f726d696e675f737472696e6773006f6e00530000001154696d655a6f6e6500555443004b0000000c00000bbe3d082f","545a0000000549"}
	builder := PacketBuilder{}

	var packet *Packet
	for _, chunk := range chunks {
		packet, _ = builder.Build(decodeHexStream(t, chunk))
	}
	if packet == nil {
		t.Error("Build expected to return 'true', but 'false' returned")
	}
}
