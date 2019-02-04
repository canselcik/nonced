package internal

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)


//236   │     def recover_nonce_reuse(self, other):
//237   │         sig2 = other.sig  # rename it
//238   │         h2 = other.h  # rename it
//239   │         # precalculate static values
//240   │         z = self.h - h2
//241   │         r_inv = inverse_mod(self.sig.r, self.n)
//242   │         #
//243   │         # tryqqqq all candidates
//244   │         #
//245   │         for candidate in (self.sig.s - sig2.s,
//246   │                           self.sig.s + sig2.s,
//247   │                           -self.sig.s - sig2.s,
//248   │                           -self.sig.s + sig2.s):
//249   │             k = (z * inverse_mod(candidate, self.n)) % self.n
//250   │             d = (((self.sig.s * k - self.h) % self.n) * r_inv) % self.n
//251   │             signingkey = SigningKey.from_secret_exponent(d, curve=self.curve)
//252   │             if signingkey.get_verifying_key().pubkey.verifies(self.h, self.sig):
//253   │                 self.signingkey = signingkey
//254   │                 self.k = k
//255   │                 self.x = d
//256   │                 return self
//257   │         assert False # could not recover private key


func TestParseTransaction(t *testing.T) {
	rawTxn := "0100000002f64c603e2f9f4daf70c2f4252b2dcdb07cc0192b7238bc9c3dacbae555baf701010000008a4730440220d47ce4" +
		"c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1022044e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6" +
		"836596b4fe9dd2f53e3e014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e2" +
		"3f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff29f841db2ba0cafa3a2a893cd1d8c3e962e8678fc61ebe89f4" +
		"15a46bc8d9854a010000008a4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad102209a5f" +
		"1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab014104dbd0c61532279cf72981c3584fc32216e0127699" +
		"635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff01a0860100" +
		"000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac00000000"


	txn := ParseTransaction(rawTxn)
	assert.NotNil(t, txn, "Failed to parse transaction")
	assert.Equal(t, "9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1", txn.Hash.String(),
		"Failed to derive txn id")
	assert.Equal(t, 2, len(txn.TxIn), "Wrong input count")
	assert.Equal(t, 1, len(txn.TxOut), "Wrong output count")

	i0sig, i0key, err := txn.TxIn[0].GetKeyAndSig()
	assert.NoError(t, err, "Error getting key/sig of the first input")
	assert.True(t, i0key.IsValid(), "invalid key from first input")

	i0sigS := hex.EncodeToString(i0sig.Signature.S.Bytes())
	assert.Equal(t, "44e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e", i0sigS,
		"Incorrect s value in signature of the first input")
	i0sigR := hex.EncodeToString(i0sig.Signature.R.Bytes())
	assert.Equal(t, "d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1", i0sigR,
		"Incorrect r value in signature of the first input")
	i0sig.
}