package internal

import (
	"github.com/piotrnar/gocoin/lib/btc"
)

func ParseTransaction(rawTxn []byte) *btc.Tx {
	tx, _ := btc.NewTx(rawTxn)
	tx.SetHash(rawTxn)
	return tx
}

//func createTrimmedTransaction(fullTxn *btc.TxPrevOut) *btc.Tx {
//	tx := btc.Tx{
//		TxIn: make([]*btc.TxIn, 0),
//		TxOut: make([]*btc.TxOut, 0),
//	}
//	fullTxn.
//
//	for _, vin := range tx.Vin {
//		inputs = append(inputs, TXInput{vin.Txid, vin.Vout, nil, nil})
//	}
//
//	for _, vout := range tx.Vout {
//		outputs = append(outputs, TXOutput{vout.Value, vout.PubKeyHash})
//	}
//
//	txCopy := Transaction{tx.ID, inputs, outputs}
//
//	return txCopy
//}
