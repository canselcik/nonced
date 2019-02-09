package decoder

import (
	"bytes"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/canselcik/nonced/internal/provider"
	"github.com/piotrnar/gocoin/lib/btc"
	"log"
)

type DecodedBitcoinTransaction struct {
	gobtcTx   *btc.Tx
	btcutilTx *btcutil.Tx
}

func DecodeBitcoinTransaction(rawTxn []byte) DecodedTransaction {
	gtx, _ := btc.NewTx(rawTxn)
	gtx.SetHash(rawTxn)

	btx, err := btcutil.NewTxFromReader(bytes.NewReader(rawTxn))
	if err != nil {
		log.Println("error in DecodeTransaction:", err.Error())
		return nil
	}
	return &DecodedBitcoinTransaction{
		gobtcTx:   gtx,
		btcutilTx: btx,
	}
}

func (tx *DecodedBitcoinTransaction) GetTransactionId() string {
	return tx.btcutilTx.Hash().String()
}

// Z values are not available if infoProvider == nil
func (tx *DecodedBitcoinTransaction) DeriveEcdsaInfo(infoProvider provider.DataProvider) []*SigHashPair {
	info := make([]*SigHashPair, 0)
	msgTx := tx.btcutilTx.MsgTx()
	for i, input := range tx.gobtcTx.TxIn {
		sig, key, err := input.GetKeyAndSig()
		if err != nil {
			log.Printf("Error in DeriveEcdsaInfo in (tx=%s, input=%d)\n", tx.GetTransactionId(), i)
			continue
		}

		res := SigHashPair{
			PublicKey: key.Bytes(false),
			R:         sig.R,
			S:         sig.S,
		}
		if infoProvider != nil {
			prevOutpoint := msgTx.TxIn[i].PreviousOutPoint
			prevTx := infoProvider.GetTransaction(&prevOutpoint.Hash)
			if prevTx == nil {
				log.Printf("Error in DeriveEcdsaInfo due to prevtx not found (tx=%s, input=%d)\n",
					tx.GetTransactionId(), i)
				continue
			}

			// TODO: Perhaps it may be not SigHashAll at all times?
			z, err := txscript.CalcSignatureHash(
				prevTx.MsgTx().TxOut[prevOutpoint.Index].PkScript,
				txscript.SigHashAll,
				msgTx,
				i,
			)
			if err != nil {
				log.Printf(
					"Error in DeriveEcdsaInfo while computing z value from prevOutpoint (tx=%s, outidx=%d)\n",
					prevOutpoint.Hash.String(), prevOutpoint.Index)
				continue
			}
			res.Z = z
		}
		info = append(info, &res)
	}
	return info
}
