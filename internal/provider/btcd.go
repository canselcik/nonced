package provider

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	zmq "github.com/pebbe/zmq4"

	log "github.com/sirupsen/logrus"
)

type BtcdProvider struct {
	*rpcclient.Client
}

func NewLocalBitcoindRpcProvider() DataProvider {
	return NewBtcdProvider("127.0.0.1:8332", "bitcoin", "password", true, true)
}

func NewBtcdProvider(host, user, pass string, httpPost, disableTls bool) DataProvider {
	client, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         host,
		User:         user,
		Pass:         pass,
		HTTPPostMode: httpPost,
		DisableTLS:   disableTls,
	}, nil)
	// TODO: leverage ntfn handlers here for realtime testing
	if err != nil {
		log.Println("Failed to create BtcdProvider:", err.Error())
		return nil
	}
	return &BtcdProvider{client}
}

func (p *BtcdProvider) Close() {
	p.Shutdown()
}

func (p *BtcdProvider) GetTransaction(txid *chainhash.Hash) (*btcutil.Tx, error) {
	bc, err := p.Client.GetRawTransaction(txid)
	if err != nil {
		return nil, fmt.Errorf("failed to GetBlockCount in BtcdProvider: %s", err.Error())
	}
	return bc, nil
}

func (p *BtcdProvider) GetTransactionFromTxId(txidStr string) (*btcutil.Tx, error) {
	txid, err := chainhash.NewHashFromStr(txidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse txidStr: %s", err.Error())
	}

	tx, err := p.GetTransaction(txid)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("GetTransaction returned nil")
	}

	return tx, nil
}

func (p *BtcdProvider) GetRawTransactionFromTxId(txidStr string) ([]byte, error) {
	txid, err := chainhash.NewHashFromStr(txidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse txidStr: %s", err.Error())
	}

	tx, err := p.GetTransaction(txid)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("GetTransaction returned nil")
	}

	return SerializeBitcoinMsgTx(tx.MsgTx())
}

func SerializeBitcoinMsgTx(msgTx *wire.MsgTx) ([]byte, error) {
	if msgTx == nil {
		return nil, errors.New("SerializeBitcoinMsgTx passed in nil")
	}

	var b bytes.Buffer
	wr := bufio.NewWriter(&b)
	err := msgTx.BtcEncode(wr, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize the txn: %s", err.Error())
	}

	err = wr.Flush()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to flush the buffer while serializing the txn: %s", err.Error())
	}
	return b.Bytes(), nil
}

type BtcdZmqStreamer struct {
	subscriber *zmq.Socket
}

func (streamer *BtcdZmqStreamer) Close() {
	if streamer.subscriber != nil {
		_ = streamer.subscriber.Close()
	}
}

func (streamer *BtcdZmqStreamer) Stream(handler func(string, []byte)) error {
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
		handler(msgType, msgBody)
	}
}

func NewBtcdZmqStreamer(connString string, topics []string) (*BtcdZmqStreamer, error) {
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
