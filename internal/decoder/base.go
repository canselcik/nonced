package decoder

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
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
	if !bytes.Equal(lhs.R.Bytes(), rhs.R.Bytes()) {
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

	// pk = Private Key (unknown at first)
	// K  = K value that was used (unknown at first)
	// N  = integer order of G (part of public key, known)

	// From Signing Definition:
	// s1 = (L1 + pk * R) / K Mod N    and     s2 = (L2 + pk * R) / K Mod N

	// Rearrange:
	// K = (L1 + pk * R) / s1 Mod N    and     K = (L2 + pk * R) / s2 Mod N

	// Set Equal:
	// (L1 + pk * R) / s1 = (L2 + pk * R) / s2     Mod N

	// Solve for pk (private key):
	// pk Mod N = (s2 * L1 - s1 * L2) / R * (s1 - s2)
	// pk Mod N = (s2 * L1 - s1 * L2) * (R * (s1 - s2)) ** -1

	pubKeyOrderInteger := lhsPk.Curve.Params().N

	l1, l2, s1l2, s2l1, firstTerm, secondTerm,
	numerator, negs1, negs2, candModOrder, invModTarget, denominator, mult, privateKey :=
		new(secp256k1.Number), new(secp256k1.Number),
		new(secp256k1.Number), new(secp256k1.Number),
		new(secp256k1.Number), new(secp256k1.Number),
		new(secp256k1.Number), new(secp256k1.Number),
		new(secp256k1.Number), new(secp256k1.Number),
		new(secp256k1.Number), new(secp256k1.Number),
		new(secp256k1.Number), new(secp256k1.Number)

	candidates := []*secp256k1.Number {
		new(secp256k1.Number), // (s1 - s2)
		new(secp256k1.Number), // (s1 + s2)
		new(secp256k1.Number), // (-s1 - s2)
		new(secp256k1.Number), // (-s1 + s2)
	}

	// Load the hash values from both SigHashPair
	l1.SetBytes(lhs.Z)
	l2.SetBytes(rhs.Z)

	// (s2 * L1)
	s2l1.Mul(&rhs.S.Int, &l1.Int)

	// (s2 * L1) % publicKeyOrderInteger
	firstTerm.Mod(&s2l1.Int, pubKeyOrderInteger)

	// (s1 * L2)
	s1l2.Mul(&lhs.S.Int, &l2.Int)

	// (s1 * L2) % publicKeyOrderInteger
	secondTerm.Mod(&s1l2.Int, pubKeyOrderInteger)

	// numerator = (((s2 * L1) % publicKeyOrderInteger) - ((s1 * L2) % publicKeyOrderInteger))
	numerator.Sub(&firstTerm.Int, &secondTerm.Int)

	// Set up all candidates due to the symmetry on the curve
	negs1.Neg(&lhs.S.Int)
	negs2.Neg(&rhs.S.Int)

	candidates[0].Sub(&lhs.S.Int, &rhs.S.Int)
	candidates[1].Add(&lhs.S.Int, &rhs.S.Int)
	candidates[2].Sub(&negs1.Int, &rhs.S.Int)
	candidates[3].Add(&negs1.Int, &rhs.S.Int)
	for _, candidate := range candidates {
		// denominator = inverse_mod(r1 * (candidate % publicKeyOrderInteger), publicKeyOrderInteger)
		candModOrder.Mod(&candidate.Int, pubKeyOrderInteger)
		invModTarget.Mul(&lhs.R.Int, &candModOrder.Int)
		denominator.ModInverse(&invModTarget.Int, pubKeyOrderInteger)

		// private_key = numerator * denominator % publicKeyOrderInteger
		mult.Mul(&numerator.Int, &denominator.Int)
		privateKey.Mod(&mult.Int, pubKeyOrderInteger)

		// Parsing the private key from bytes
		derivedPriv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKey.Bytes())

		// Validating the candidate
		signedHash, err := derivedPriv.Sign(lhs.Z)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with a derived private key: %s", err.Error())
		}
		if signedHash.Verify(lhs.Z, lhsPk) {
			return derivedPriv, nil
		}
	}
	return nil, errors.New("unable to derive a private key from the inputs despite everything looking okay")
}