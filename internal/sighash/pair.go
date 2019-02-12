package sighash

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

type SHPair struct {
	R         *big.Int
	S         *big.Int
	Z         []byte
	PublicKey []byte
}

var (
	WarnNoRValueReuse  = errors.New("no R value reuse detected in given SHPair for RecoverPrivateKey")
	WarnPubkeyMismatch = errors.New("sigHashPair w/ different public keys are not candidates for RecoverPrivateKey")

	ErrMissingZValue = errors.New("missing Z value in SHPair for RecoverPrivateKey, " +
		"make sure to provide a DataProvider to DeriveEcdsaInfo")
	ErrIdenticalInputs = errors.New("need two distinct SHPair for RecoverPrivateKey")
	ErrNilInput        = errors.New("both inputs need to be non-nil SHPair")
	ErrCorruptPubkey   = errors.New("failed to parse given public key")
	ErrNoResult        = errors.New("unable to derive a private key from the inputs despite everything looking okay")
)

func (lhs *SHPair) RecoverPrivateKey(rhs *SHPair) (*btcec.PrivateKey, error) {
	// Make sure we have two distinct SHPair
	if lhs == nil || rhs == nil {
		return nil, ErrNilInput
	}
	if lhs == rhs {
		return nil, ErrIdenticalInputs
	}

	// Make sure both SHPair have Z values from the DeriveEcdsaInfo step
	if lhs.Z == nil || rhs.Z == nil {
		return nil, ErrMissingZValue
	}

	// Check for nonce reuse
	if !bytes.Equal(lhs.R.Bytes(), rhs.R.Bytes()) {
		return nil, WarnNoRValueReuse
	}

	// Check both pubkeys are valid and equal each other
	lhsPk, err := btcec.ParsePubKey(lhs.PublicKey, btcec.S256())
	if err != nil {
		return nil, ErrCorruptPubkey
	}
	rhsPk, err := btcec.ParsePubKey(rhs.PublicKey, btcec.S256())
	if err != nil {
		return nil, ErrCorruptPubkey
	}
	if !lhsPk.IsEqual(rhsPk) {
		return nil, WarnPubkeyMismatch
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
		new(big.Int), new(big.Int),
		new(big.Int), new(big.Int),
		new(big.Int), new(big.Int),
		new(big.Int), new(big.Int),
		new(big.Int), new(big.Int),
		new(big.Int), new(big.Int),
		new(big.Int), new(big.Int)

	candidates := []*big.Int{
		new(big.Int), // (s1 - s2)
		new(big.Int), // (s1 + s2)
		new(big.Int), // (-s1 - s2)
		new(big.Int), // (-s1 + s2)
	}

	// Load the hash values from both SHPair
	l1.SetBytes(lhs.Z)
	l2.SetBytes(rhs.Z)

	// (s2 * L1)
	s2l1.Mul(rhs.S, l1)

	// (s2 * L1) % publicKeyOrderInteger
	firstTerm.Mod(s2l1, pubKeyOrderInteger)

	// (s1 * L2)
	s1l2.Mul(lhs.S, l2)

	// (s1 * L2) % publicKeyOrderInteger
	secondTerm.Mod(s1l2, pubKeyOrderInteger)

	// numerator = (((s2 * L1) % publicKeyOrderInteger) - ((s1 * L2) % publicKeyOrderInteger))
	numerator.Sub(firstTerm, secondTerm)

	// Set up all candidates due to the symmetry on the curve
	negs1.Neg(lhs.S)
	negs2.Neg(rhs.S)

	candidates[0].Sub(lhs.S, rhs.S)
	candidates[1].Add(lhs.S, rhs.S)
	candidates[2].Sub(negs1, rhs.S)
	candidates[3].Add(negs1, rhs.S)
	for _, candidate := range candidates {
		// denominator = inverse_mod(r1 * (candidate % publicKeyOrderInteger), publicKeyOrderInteger)
		candModOrder.Mod(candidate, pubKeyOrderInteger)
		invModTarget.Mul(lhs.R, candModOrder)
		denominator.ModInverse(invModTarget, pubKeyOrderInteger)

		// private_key = numerator * denominator % publicKeyOrderInteger
		mult.Mul(numerator, denominator)
		privateKey.Mod(mult, pubKeyOrderInteger)

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
	return nil, ErrNoResult
}
