package internal

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/piotrnar/gocoin/lib/btc"
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

func TestAsd(t *testing.T) {
	addressStr := "12gpXQVcCL2qhTNQgyLVdCFG2Qs2px98nV"
	address, err := btcutil.DecodeAddress(addressStr, &chaincfg.MainNetParams)
	assert.NoError(t, err)

	// Create a public key script that pays to the address.
	script, err := txscript.PayToAddrScript(address)
	assert.NoError(t, err)
	fmt.Printf("sha2(Script Hex): %x\n", btc.Sha2Sum(script))

	disasm, err := txscript.DisasmString(script)
	assert.NoError(t, err)
	fmt.Println("Script Disassembly:", disasm)
}

var _vulnTxnId = "9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1"
var _vulnTxn, _ = hex.DecodeString("0100000002f64c603e2f9f4daf70c2f4252b2dcdb07cc0192b7238bc9c3dacbae555baf701010000008a4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1022044e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff29f841db2ba0cafa3a2a893cd1d8c3e962e8678fc61ebe89f415a46bc8d9854a010000008a4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad102209a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff01a0860100000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac00000000")
var _vulnParsedTxn, _ = btcutil.NewTxFromReader(bytes.NewReader(_vulnTxn))

var _prevTxnIdA = "01f7ba55e5baac3d9cbc38722b19c07cb0cd2d2b25f4c270af4d9f2f3e604cf6"
var _prevTxnA, _ = hex.DecodeString("0100000001c4c86ae540d340471b03833cb67386b060a7a5632f1ee730c71ef6909e90eb9c000000008b4830450221008787140a00fdb05e55ef660f54c3f51d849935d14bc2e2c60fb97a051a1da3c70220797b5eb265246e63cb061ab277c541a3ba4237d5b3c5fe94b6af9400723a879001410404c6d628a12e1cbf01b1d8316cb1c09a38163369f1113a26513565a1a2445e2e12fdac748cec243442c6185e5e2c2647f993c88aff95d922f65117d73da566ccffffffff02d0dcf705000000001976a914fc41cee355d10b863137006382c809aec1ddf33c88acd0fb0100000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac00000000")
var _prevParsedTxnA, _ = btcutil.NewTxFromReader(bytes.NewReader(_prevTxnA))

var _prevTxnIdB = "4a85d9c86ba415f489be1ec68f67e862e9c3d8d13c892a3afacaa02bdb41f829"
var _prevTxnB, _ = hex.DecodeString("0100000001c4c86ae540d340471b03833cb67386b060a7a5632f1ee730c71ef6909e90eb9c010000008a4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1022012a8c1d5c602e382c178fbfcb957e8ecc347f1baf78a206f20a97ff4c433e146014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff0250c30000000000001976a914019453ca35e7cdc43118dda7bc81ee981bd6f92488ac204e0000000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac00000000")
var _prevParsedTxnB, _ = btcutil.NewTxFromReader(bytes.NewReader(_prevTxnB))

var _sharedR = "d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1"

func TestDeriveTxnId(t *testing.T) {
	assert.Equal(t, _vulnTxnId, _vulnParsedTxn.Hash().String(), "Failed to derive txn id from raw txn")
	assert.Equal(t, _prevTxnIdA, _prevParsedTxnA.Hash().String(), "Failed to derive txn id from raw txn")
	assert.Equal(t, _prevTxnIdB, _prevParsedTxnB.Hash().String(), "Failed to derive txn id from raw txn")
}

func TestTxnIO(t *testing.T) {
	assert.Equal(t, "4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1022044e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff",
		hex.EncodeToString(_vulnParsedTxn.MsgTx().TxIn[0].SignatureScript), "wrong input signature")
	assert.Equal(t, "4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad102209a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff",
		hex.EncodeToString(_vulnParsedTxn.MsgTx().TxIn[1].SignatureScript), "wrong input signature")

	// Pk
	vulnTxnPkScript, _ := txscript.ParsePkScript(_vulnParsedTxn.MsgTx().TxOut[0].PkScript)

	// Output Addr
	lastOutAddr, _ := vulnTxnPkScript.Address(&chaincfg.MainNetParams)
	assert.Equal(t, "1BFhrfTTZP3Nw4BNy4eX4KFLsn9ZeijcMm", lastOutAddr.String(), "Wrong output addr")

	// Input 0
	assert.Equal(t, _prevTxnIdA, _vulnParsedTxn.MsgTx().TxIn[0].PreviousOutPoint.Hash.String(), "Incorrect prev txnid")
	assert.Equal(t, uint32(1), _vulnParsedTxn.MsgTx().TxIn[0].PreviousOutPoint.Index, "Incorrect prev txn output idx")

	// Input 1
	assert.Equal(t, _prevTxnIdB, _vulnParsedTxn.MsgTx().TxIn[1].PreviousOutPoint.Hash.String(), "Incorrect prev txnid")
	assert.Equal(t, uint32(1), _vulnParsedTxn.MsgTx().TxIn[1].PreviousOutPoint.Index, "Incorrect prev txn output idx")
}

func TestZValueExtraction(t *testing.T) {
	// SignatureScript creates an input signature script for tx to spend BTC sent
	// from a previous output to our way. tx must include all
	// transaction inputs and outputs, however txin scripts are allowed to be filled
	// or empty. The returned script is calculated to be used as the idx'th txin
	// sigscript for tx. subscript is the PkScript of the previous output being used
	// as the idx'th input.
	// Note the PKScriptLocs conv wrapper.
	inputHashA, _ := txscript.CalcSignatureHash(_prevParsedTxnA.MsgTx().TxOut[1].PkScript, txscript.SigHashAll, _vulnParsedTxn.MsgTx(), 0)
	inputHashB, _ := txscript.CalcSignatureHash(_prevParsedTxnB.MsgTx().TxOut[1].PkScript, txscript.SigHashAll, _vulnParsedTxn.MsgTx(), 1)
	assert.Equal(t, "c0e2d0a89a348de88fda08211c70d1d7e52ccef2eb9459911bf977d587784c6e", hex.EncodeToString(inputHashA), "wrong z1")
	assert.Equal(t, "17b0f41c8c337ac1e18c98759e83a8cccbc368dd9d89e5f03cb633c265fd0ddc", hex.EncodeToString(inputHashB), "wrong z2")
}

func TestRSValExtraction(t *testing.T) {
	// Parse
	txn := ParseTransaction(_vulnTxn)
	assert.NotNil(t, txn, "Failed to parse transaction")

	// Input 0
	i0sig, i0key, err := txn.TxIn[0].GetKeyAndSig()
	assert.NoError(t, err, "Error getting key/sig of the first input")
	// -- pubkey
	assert.True(t, i0key.IsValid(), "invalid key from first input")
	assert.Equal(t, "04dbd0c61532279cf72981c358"+
		"4fc32216e0127699635c2789f549e0730c059b81ae13301"+
		"6a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a8"+
		"29b449c5ff", hex.EncodeToString(i0key.Bytes(false)))
	// -- sigS
	i0sigS := hex.EncodeToString(i0sig.Signature.S.Bytes())
	assert.Equal(t, "44e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e", i0sigS,
		"Incorrect s value in signature of the first input")
	// -- sigR
	i0sigR := hex.EncodeToString(i0sig.Signature.R.Bytes())
	assert.Equal(t, _sharedR, i0sigR, "Incorrect r value in signature of the first input")

	// Input 1
	i1sig, i1key, err := txn.TxIn[1].GetKeyAndSig()
	assert.NoError(t, err, "Error getting key/sig of the second input")
	// -- pubkey
	assert.True(t, i1key.IsValid(), "invalid key from second input")
	assert.Equal(t, "04dbd0c61532279cf72981c358"+
		"4fc32216e0127699635c2789f549e0730c059b81ae13301"+
		"6a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a8"+
		"29b449c5ff", hex.EncodeToString(i1key.Bytes(false)))
	// -- sigS
	assert.Equal(t, "9a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab",
		hex.EncodeToString(i1sig.Signature.S.Bytes()),
		"Incorrect s value in signature of the second input",
	)
	// -- sigR
	assert.Equal(t, _sharedR,
		hex.EncodeToString(i1sig.Signature.R.Bytes()),
		"Incorrect r value in signature of the second input")
}
