package pgsql

const (
	OriginBackend = 0x01
	OriginFrontend = 0x02

	// Рассылается сервером.
	// Длина сообщения всегда 8 байт.
	authenticationOk = 0x52

	// Рассылается сервером.
	parameterStatus = 0x53

	// Рассылается сервером.
	// Длина сообщения всегда 12 байт.
	backendKeyData = 0x4b

	// Рассылается сервером.
	// Длина сообщения всегда 5 байт.
	readyForQuery = 0x5a

	// Рассылается клиентом.
	parse = 0x50
)
