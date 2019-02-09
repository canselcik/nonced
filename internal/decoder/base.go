package decoder

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/canselcik/nonced/internal/provider"
	"github.com/piotrnar/gocoin/lib/secp256k1"
	"os/exec"
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

// def recover_nonce_reuse(self, other):
//     z = self.h - h2
//     r_inv = inverse_mod(self.sig.r, self.n)

//     for candidate in (self.sig.s - sig2.s,
//                       self.sig.s + sig2.s,
//                       -self.sig.s - sig2.s,
//                       -self.sig.s + sig2.s):
//         k = (z * inverse_mod(candidate, self.n)) % self.n
//         d = (((self.sig.s * k - self.h) % self.n) * r_inv) % self.n
//         signingkey = SigningKey.from_secret_exponent(d, curve=self.curve)
//         if signingkey.get_verifying_key().pubkey.verifies(self.h, self.sig):
//             self.signingkey = signingkey
//             self.k = k
//             self.x = d
//             return self
//     assert False # could not recover private key
//
// private key = (z1 * s2 - z2 * s1) / (r * (s1 - s2))
func (lhs *SigHashPair) RecoverPrivateKey(rhs *SigHashPair) (*btcec.PrivateKey, error) {
	// Make sure we have two distinct SigHashPair
	if lhs == nil || rhs == nil {
		return nil, errors.New("RecoverPrivateKey needs non-nil SigHashPair")
	}
	if lhs == rhs {
		return nil, errors.New("need two distinct SigHashPair for RecoverPrivateKey")
	}

	// Make sure both SigHashPair have Z values from the DeriveEcdsaInfo step
	if lhs.Z == nil || rhs.Z == nil {
		return nil, errors.New("missing Z value in SigHashPair for RecoverPrivateKey, " +
			"make sure to provide a DataProvider to DeriveEcdsaInfo")
	}

	// Check for nonce reuse
	if bytes.Equal(lhs.R.Bytes(), rhs.R.Bytes()) {
		return nil, errors.New("no R value reuse detected in given SigHashPair for RecoverPrivateKey")
	}

	// Check both pubkeys are valid and equal each other
	lhsPk, err := btcec.ParsePubKey(lhs.PublicKey, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("failed to parse lhsPubKey: %s", err.Error())
	}
	rhsPk, err := btcec.ParsePubKey(rhs.PublicKey, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("failed to parse rhsPubKey: %s", err.Error())
	}
	if !lhsPk.IsEqual(rhsPk) {
		return nil, errors.New("sigHashPair w/ different public keys are not candidates for RecoverPrivateKey")
	}

	output, err := exec.Command("reuse.py",
		hex.EncodeToString(lhs.PublicKey),
		hex.EncodeToString(lhs.R.Bytes()),
		hex.EncodeToString(lhs.Z),
		hex.EncodeToString(lhs.S.Bytes()),
		hex.EncodeToString(rhs.Z),
		hex.EncodeToString(rhs.S.Bytes()),
	).Output()
	if err != nil {
		return nil, fmt.Errorf("failed derivation: %s", err.Error())
	}

	derivedPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), output)
	if derivedPriv == nil {
		return nil, errors.New("failed to unmarshal the derived private key into an ecdsa.PrivateKey")
	}
	return derivedPriv, nil
}