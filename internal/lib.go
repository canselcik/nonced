package internal

import (
	"encoding/hex"
	"github.com/piotrnar/gocoin/lib/btc"
	"log"
)

func ParseTransaction(hexEncodedTxn string) *btc.Tx {
	rawTxn, err := hex.DecodeString(hexEncodedTxn)
	if err != nil {
		log.Println("Decode Error in ParseTransaction:", err.Error())
		return nil
	}

	tx, _ := btc.NewTx(rawTxn)
	tx.SetHash(rawTxn)
	return tx
}