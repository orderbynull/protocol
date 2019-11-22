package pgsql

import (
	"encoding/hex"
	"fmt"
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

func Test_IsSSLRequest_Valid_Packet(t *testing.T) {
	stream := "0000000804d2162f"
	if !IsSSLRequest(decodeHexStream(t, stream)) {
		t.Error("IsSSLRequest expected to return 'true', but 'false' returned")
	}
}

func Test_IsSSLRequest_InValid_Packet(t *testing.T) {
	invalidPackets := []string{
		"",
		// любые 8 байт, чтобы прошла проверка на длину пакета
		"0000000f0f0f0f00",
		// ожидаемая длина пакета, которая не совпадает с фактической длиной
		"00000070",
		// верный пакет за исключением второй четверки байт(код пакета)
		"000000080fd2162f",
	}
	for _, packet := range invalidPackets {
		if IsSSLRequest(decodeHexStream(t, packet)) {
			t.Error("IsStartupMessage expected to return 'false', but 'true' returned")
		}
	}
}

func Test_IsStartupMessage_Valid_Packet(t *testing.T) {
	stream := "0000007000030000757365720079615f74657374696e6700646174616261736500706f73746772657300636c69656e745f656e636f64696e67005554463800446174655374796c650049534f0054696d655a6f6e65005554430065787472615f666c6f61745f64696769747300320000"
	if !IsStartupMessage(decodeHexStream(t, stream)) {
		t.Error("IsStartupMessage expected to return 'true', but 'false' returned")
	}
}

func Test_IsStartupMessage_InValid_Packet(t *testing.T) {
	invalidPackets := []string{
		"",
		// любые 8 байт, чтобы прошла проверка на длину пакета
		"0000000f0f0f0f00",
		// ожидаемая длина пакета, которая не совпадает с фактической длиной
		"00000070",
		// верный пакет за исключением второй четверки байт(версия протокола)
		"0000007001030000757365720079615f74657374696e6700646174616261736500706f73746772657300636c69656e745f656e636f64696e67005554463800446174655374796c650049534f0054696d655a6f6e65005554430065787472615f666c6f61745f64696769747300320000",
	}
	for _, packet := range invalidPackets {
		if IsStartupMessage(decodeHexStream(t, packet)) {
			t.Error("IsStartupMessage expected to return 'false', but 'true' returned")
		}
	}
}

func Test_IsValidPacket_Valid_Packet(t *testing.T) {
	fmt.Printf("%v\n", IsValidPacket(decodeHexStream(t, "52000000080000000053000000166170706c69636174696f6e5f6e616d6500005300000019636c69656e745f656e636f64696e670055544638005300000017446174655374796c650049534f2c204d4459005300000019696e74656765725f6461746574696d6573006f6e00530000001b496e74657276616c5374796c6500706f73746772657300530000001569735f737570657275736572006f66660053000000197365727665725f656e636f64696e67005554463800530000001a7365727665725f76657273696f6e00392e362e313000530000002573657373696f6e5f617574686f72697a6174696f6e0079615f74657374696e670053000000237374616e646172645f636f6e666f726d696e675f737472696e6773006f6e00530000001154696d655a6f6e6500555443004b0000000c00000bbe3d082f545a0000000549")))
}


