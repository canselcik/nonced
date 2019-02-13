package sighash

import (
	"bytes"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/canselcik/nonced/internal/provider"
	log "github.com/sirupsen/logrus"
)

type SHPairBucket struct {
	Pairs        []*SHPair
	infoProvider provider.DataProvider
}

func NewSHPairBucket(infoProvider provider.DataProvider) *SHPairBucket {
	return &SHPairBucket{
		Pairs:        make([]*SHPair, 0),
		infoProvider: infoProvider,
	}
}

var (
	ErrTxnDecode          = errors.New("failed to decode transaction")
	WarnEmptySigSkip      = errors.New("skipping due to empty sig")
	WarnWitnessSkip       = errors.New("skipping due to txWitness")
	WarnSigOffsetSkip     = errors.New("skipping due to sig offset being out of bounds")
	WarnSigParseSkip      = errors.New("skipping due to failure to parse signature")
	WarnKeyLenOffsetSkip  = errors.New("skipping due to key len index being out of bounds")
	WarnKeyOffsetSkip     = errors.New("skipping due to key end being out of bounds")
	WarnKeyParseSkip      = errors.New("skipping due to failure to parse key")
	WarnCantFindPrevOut   = errors.New("skipping due to failure to get prevOut for input")
	WarnFailedZValExtract = errors.New("skipping due to failure extract Z value for prevOut")
	WarnMofNSkip          = errors.New("skipping due to m-of-n")
)

func (bucket *SHPairBucket) AddRawTx(rawTxn []byte) (int, map[int]error) {
	btx, err := btcutil.NewTxFromReader(bytes.NewReader(rawTxn))
	if err != nil {
		return 0, map[int]error{
			-1: ErrTxnDecode,
		}
	}
	return bucket.AddTx(btx.MsgTx())
}

func (bucket *SHPairBucket) AddTx(msgTx *wire.MsgTx) (int, map[int]error) {
	extracted := 0
	errMap := make(map[int]error, 0)

	for i, input := range msgTx.TxIn {
		ss := input.SignatureScript
		if len(ss) == 0 {
			errMap[i] = WarnEmptySigSkip
			continue
		}

		if msgTx.HasWitness() {
			errMap[i] = WarnWitnessSkip
			continue
		}

		if ss[0] == txscript.OP_0 {
			errMap[i] = WarnMofNSkip
			continue
		}

		sigBegin := 1
		sigLen := int(ss[0])
		sigEnd := sigBegin + sigLen
		if len(ss) < sigEnd {
			errMap[i] = WarnSigOffsetSkip
			continue
		}

		sigslice := ss[sigBegin:sigEnd]
		sig, err := btcec.ParseSignature(sigslice, btcec.S256())
		if err != nil {
			errMap[i] = WarnSigParseSkip
			continue
		}

		offs := sigBegin + sigLen
		if len(ss) <= offs {
			errMap[i] = WarnKeyLenOffsetSkip
			continue
		}
		keyLen := int(ss[offs])
		keyBegin := offs + 1
		keyEnd := keyBegin + keyLen
		if len(ss) < keyEnd {
			errMap[i] = WarnKeyOffsetSkip
			continue
		}

		keyslice := ss[keyBegin:keyEnd]
		key, err := btcec.ParsePubKey(keyslice, btcec.S256())
		if err != nil {
			errMap[i] = WarnKeyParseSkip
			continue
		}

		res := SHPair{
			PublicKey: key.SerializeUncompressed(),
			R:         sig.R,
			S:         sig.S,
		}

		prevOutpoint := msgTx.TxIn[i].PreviousOutPoint
		prevTx, err := bucket.infoProvider.GetTransaction(&prevOutpoint.Hash)
		if err != nil {
			errMap[i] = err
			continue
		}
		if prevTx == nil {
			errMap[i] = WarnCantFindPrevOut
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
			errMap[i] = WarnFailedZValExtract
			continue
		}
		res.Z = z
		bucket.Pairs = append(bucket.Pairs, &res)
		extracted++
	}
	return extracted, errMap
}

func (bucket *SHPairBucket) Solve() []*btcec.PrivateKey {
	if len(bucket.Pairs) < 2 {
		log.Println("Solve() needs at least two SHPair in SHPairBucket")
		return nil
	}

	recovered := make([]*btcec.PrivateKey, 0)
	for i := 0; i < len(bucket.Pairs)-1; i++ {
		lhs := bucket.Pairs[i]
		for _, rhs := range bucket.Pairs[i+1:] {
			rec, err := lhs.RecoverPrivateKey(rhs)
			if err != nil {
				if err != WarnNoRValueReuse && err != WarnPubkeyMismatch {
					log.Println("Error in Solve():", err.Error())
				}
			}
			if rec != nil {
				recovered = append(recovered, rec)
			}
		}
	}
	return recovered
}
