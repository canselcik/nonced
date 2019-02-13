package provider

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type DataProvider interface {
	GetTransaction(txid *chainhash.Hash) (*btcutil.Tx, error)
	GetRawTransactionFromTxId(txidStr string) ([]byte, error)

	GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error)
	GetBlockCount() (int64, error)
}
