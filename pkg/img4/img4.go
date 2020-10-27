package img4

type Image4 struct {
	Payload *Image4Payload
	Manifest *Image4Manifest
}

type Image4Payload struct {
	Data []byte
}

type Image4Manifest struct {
	Data map[string][]byte
}
