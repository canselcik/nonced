package realtime

type StreamerCallback func(string, []byte)

type Streamer interface {
	Stream(callback StreamerCallback) error
	Close()
}
