package internal

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/canselcik/nonced/internal/provider"
	"github.com/canselcik/nonced/internal/sighash"
	"github.com/stretchr/testify/mock"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockedDataSource struct {
	mock.Mock
}

func (m *MockedDataSource) GetTransaction(txid *chainhash.Hash) *btcutil.Tx {
	retArgs := m.Called(txid)
	cast, _ := retArgs.Get(0).(*btcutil.Tx)
	return cast
}

func (m *MockedDataSource) GetRawTransactionFromTxId(txidStr string) ([]byte, error) {
	retArgs := m.Called(txidStr)
	cast, _ := retArgs.Get(0).([]byte)
	return cast, retArgs.Error(1)
}

var tx9ec4b, _ = hex.DecodeString("0100000002f64c603e2f9f4daf70c2f4252b2dcdb07" +
	"cc0192b7238bc9c3dacbae555baf701010000008a4730440220d47ce4c025c35ec440bc81d998" +
	"34a624875161a26bf56ef7fdc0f5d52f843ad1022044e1ff2dfd8102cf7a47c21d5c9fd570161" +
	"0d04953c6836596b4fe9dd2f53e3e014104dbd0c61532279cf72981c3584fc32216e012769963" +
	"5c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a82" +
	"9b449c5ffffffffff29f841db2ba0cafa3a2a893cd1d8c3e962e8678fc61ebe89f415a46bc8d9" +
	"854a010000008a4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f" +
	"5d52f843ad102209a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5b" +
	"ab014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133" +
	"016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff01a0860100" +
	"000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac00000000")

var id01f7ba, _ = chainhash.NewHashFromStr("01f7ba55e5baac3d9cbc38722b19c07cb0cd2d2b25f4c270af4d9f2f3e604cf6")
var tx01f7ba, _ = hex.DecodeString("0100000001c4c86ae540d340471b03833cb67386b06" +
	"0a7a5632f1ee730c71ef6909e90eb9c000000008b4830450221008787140a00fdb05e55ef660f5" +
	"4c3f51d849935d14bc2e2c60fb97a051a1da3c70220797b5eb265246e63cb061ab277c541a3ba4" +
	"237d5b3c5fe94b6af9400723a879001410404c6d628a12e1cbf01b1d8316cb1c09a38163369f11" +
	"13a26513565a1a2445e2e12fdac748cec243442c6185e5e2c2647f993c88aff95d922f65117d73" +
	"da566ccffffffff02d0dcf705000000001976a914fc41cee355d10b863137006382c809aec1ddf" +
	"33c88acd0fb0100000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac000" +
	"00000")

var id4a85d9, _ = chainhash.NewHashFromStr("4a85d9c86ba415f489be1ec68f67e862e9c3d8d13c892a3afacaa02bdb41f829")
var tx4a85d9, _ = hex.DecodeString("0100000001c4c86ae540d340471b03833cb67386b06" +
	"0a7a5632f1ee730c71ef6909e90eb9c010000008a4730440220d47ce4c025c35ec440bc81d9983" +
	"4a624875161a26bf56ef7fdc0f5d52f843ad1022012a8c1d5c602e382c178fbfcb957e8ecc347f" +
	"1baf78a206f20a97ff4c433e146014104dbd0c61532279cf72981c3584fc32216e0127699635c2" +
	"789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b44" +
	"9c5ffffffffff0250c30000000000001976a914019453ca35e7cdc43118dda7bc81ee981bd6f92" +
	"488ac204e0000000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac00000" +
	"000")

func TestNewAPI(t *testing.T) {
	ds := new(MockedDataSource)
	parsed01f7ba, _ := btcutil.NewTxFromBytes(tx01f7ba)
	parsed4a85d9, _ := btcutil.NewTxFromBytes(tx4a85d9)

	ds.On("GetTransaction", id01f7ba).Return(parsed01f7ba)
	ds.On("GetTransaction", id4a85d9).Return(parsed4a85d9)

	//ds := provider.NewBtcdProvider("localhost:8332", "admin", "admin", true, true)
	solveBucket := sighash.NewSHPairBucket(ds)
	extractedCount := solveBucket.Add(tx9ec4b)
	assert.Equal(t, 2, extractedCount, "wrong number of SHPair extractions")

	r := "d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1"
	pubkey := "04dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae13301" +
		"6a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff"
	for i, entry := range solveBucket.Pairs {
		assert.Equal(t, pubkey,
			hex.EncodeToString(entry.PublicKey), "failed to extract public key")
		assert.Equal(t, r,
			hex.EncodeToString(entry.R.Bytes()), "failed to extract r")

		switch i {
		case 0:
			assert.Equal(t, "44e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e",
				hex.EncodeToString(entry.S.Bytes()), "failed to extract r on input 0")
			assert.Equal(t, "c0e2d0a89a348de88fda08211c70d1d7e52ccef2eb9459911bf977d587784c6e",
				hex.EncodeToString(entry.Z), "failed to extract z on input 0")
		case 1:
			assert.Equal(t, "9a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab",
				hex.EncodeToString(entry.S.Bytes()), "failed to extract r on input 1")
			assert.Equal(t, "17b0f41c8c337ac1e18c98759e83a8cccbc368dd9d89e5f03cb633c265fd0ddc",
				hex.EncodeToString(entry.Z), "failed to extract z on input 1")
		}
	}

	solutionSet := solveBucket.Solve()
	assert.Equal(t, 1, len(solutionSet),
		"wrong number of PrivateKey solutions in a nonce reuse scenario")
	assert.NotNil(t, solutionSet[0], "derived privateKey is nil despite no errors")
	assert.Equal(t, "c477f9f65c22cce20657faa5b2d1d8122336f851a508a1ed04e479c34985bf96",
		hex.EncodeToString(solutionSet[0].Serialize()), "derived incorrect privateKey")

	ds.AssertExpectations(t)
}

func TestNotBreakable(t *testing.T) {
	ds := provider.NewBtcdProvider("localhost:8332", "admin", "admin", true, true)
	solveBucket := sighash.NewSHPairBucket(ds)

	tx, err := ds.GetRawTransactionFromTxId("9124ea4043247e6fd27712d92685cdad6ea29f654ae383424ca3af14efe50b21")
	assert.NoError(t, err, "failed to get txn by id")

	extractedCount := solveBucket.Add(tx)
	assert.Equal(t, 3, extractedCount, "wrong number of SHPair extractions")

	solutions := solveBucket.Solve()
	assert.Equal(t, 0, len(solutions), "wrong number of SHPair solutions")

}

func TestDataProviders(t *testing.T) {
	is := provider.NewInsightProvider()
	bs := provider.NewBtcdProvider("localhost:8332", "admin", "admin", true, true)

	hsh, _ := chainhash.NewHashFromStr("9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1")
	bst := bs.GetTransaction(hsh)
	ist := is.GetTransaction(hsh)
	assert.Equal(t, bst, ist, "insight and btcd in disagrement")
}
