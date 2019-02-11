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
	"log"
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

func (p *BtcdProvider) GetTransaction(txid *chainhash.Hash) *btcutil.Tx {
	bc, err := p.Client.GetRawTransaction(txid)
	if err != nil {
		log.Println("Failed to GetBlockCount in BtcdProvider:", err.Error())
		return nil
	}
	return bc
}

func (p *BtcdProvider) GetRawTransactionFromTxId(txidStr string) ([]byte, error) {
	txid, err := chainhash.NewHashFromStr(txidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse txidStr: %s", err.Error())
	}

	tx := p.GetTransaction(txid)
	if tx == nil {
		return nil, errors.New("GetTransaction returned nil")
	}

	var b bytes.Buffer
	wr := bufio.NewWriter(&b)
	err = tx.MsgTx().BtcEncode(wr, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the transaction: %s", err.Error())
	}
	err = wr.Flush()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to flush the buffer while encoding the transaction: %s", err.Error())
	}
	return b.Bytes(), nil
}
