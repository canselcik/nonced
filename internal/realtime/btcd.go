package realtime

import (
	"fmt"
	zmq "github.com/pebbe/zmq4"
)

type BtcdZmqStreamer struct {
	subscriber *zmq.Socket
}

func (streamer *BtcdZmqStreamer) Close() {
	if streamer.subscriber != nil {
		_ = streamer.subscriber.Close()
	}
}

func (streamer *BtcdZmqStreamer) Stream(callback StreamerCallback) error {
	if streamer.subscriber == nil {
		return fmt.Errorf("subscriber not initialized")
	}
	for {
		message, err := streamer.subscriber.RecvMessageBytes(zmq.SNDMORE)
		if err != nil {
			return err
		}
		if message == nil || len(message) != 3 {
			return fmt.Errorf("received nil or a non-3-part message from ZMQ")
		}

		msgType := string(message[0])
		msgBody := message[1]
		callback(msgType, msgBody)
	}
}

func NewBtcdZmqStreamer(connString string, topics []string) (Streamer, error) {
	subscriber, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		return nil, err
	}

	err = subscriber.Connect(connString)
	if err != nil {
		return nil, err
	}

	for _, topic := range topics {
		err = subscriber.SetSubscribe(topic)
		if err != nil {
			return nil, err
		}
	}

	return &BtcdZmqStreamer{subscriber}, nil
}
