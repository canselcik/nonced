package decoder

import (
	"github.com/canselcik/nonced/internal/provider"
	"github.com/piotrnar/gocoin/lib/secp256k1"
)

type SigHashPair struct {
	PublicKey []byte
	Z []byte
	R secp256k1.Number
	S secp256k1.Number
}

type DecodedTransaction interface {
	GetTransactionId() string
	DeriveEcdsaInfo(infoProvider provider.DataProvider) []*SigHashPair
}