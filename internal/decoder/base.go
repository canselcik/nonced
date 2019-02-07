package decoder

import (
	"github.com/canselcik/nonced/internal/provider"
	"github.com/piotrnar/gocoin/lib/secp256k1"
)

type SigHashPair struct {
	R         secp256k1.Number
	S         secp256k1.Number
	Z         []byte
	PublicKey []byte
}

type DecodedTransaction interface {
	GetTransactionId() string
	DeriveEcdsaInfo(infoProvider provider.DataProvider) []*SigHashPair
}
