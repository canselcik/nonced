package provider

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcutil"
	"log"
)

type BtcdProvider struct {
	*rpcclient.Client
}

func NewBtcdProvider(host, user, pass string, httpPost, disableTls bool) DataProvider {
	client, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         host,
		User:         user,
		Pass:         pass,
		HTTPPostMode: httpPost,
		DisableTLS:   disableTls,
	}, nil)
	if err != nil {
		log.Println("Failed to create BtcdProvider:", err.Error())
		return nil
	}
	return &BtcdProvider{client}
}

func (p *BtcdProvider) Close() {
	p.Client.Shutdown()
}

func (p *BtcdProvider) GetBlockCount() *int64 {
	bc, err := p.Client.GetBlockCount()
	if err != nil {
		log.Println("Failed to GetBlockCount in BtcdProvider:", err.Error())
		return nil
	}
	return &bc
}


func (p *BtcdProvider) GetTransaction(txid *chainhash.Hash) *btcutil.Tx {
	bc, err := p.Client.GetRawTransaction(txid)
	if err != nil {
		log.Println("Failed to GetBlockCount in BtcdProvider:", err.Error())
		return nil
	}
	return bc
}