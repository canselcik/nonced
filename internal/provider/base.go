package provider

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
)

type DataProvider interface {
	GetTransaction(txid *chainhash.Hash) *btcutil.Tx
}
