package provider

import (
	"bufio"
	"errors"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type InsightProvider struct {
	address string
	*rpcclient.Client
}

func NewCustomInsightProvider(address string) DataProvider {
	return &InsightProvider{
		address: address,

	}
}

func NewInsightProvider() DataProvider {
	return NewCustomInsightProvider("https://insight.bitpay.com")
}

func (p *InsightProvider) GetBlockCount() *int64 {
	bc, err := p.Client.GetBlockCount()
	if err != nil {
		log.Println("Failed to GetBlockCount in BtcdProvider:", err.Error())
		return nil
	}
	return &bc
}

func (p *InsightProvider) GetTransaction(txid *chainhash.Hash) *btcutil.Tx {
	client := http.Client{
		Timeout: time.Duration(5 * time.Second),
	}

	url := fmt.Sprintf("%s/api/rawtx/%s", p.address, txid.String())
	resp, err := client.Get(url)
	if err != nil {
		log.Println("Failed to GetTransaction in InsightProvider:", err.Error())
		return nil
	}

	if resp.StatusCode != 200 {
		log.Println("Got", resp.StatusCode, "from InsightProvider for txn", txid.String())
		return nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read response of GetTransaction in InsightProvider:", err.Error())
		return nil
	}

	var raw struct{
		RawTx string `json:"rawtx"`
	}
	err = json.Unmarshal(body, &raw)
	if err != nil {
		log.Println("Failed to parse response of GetTransaction in InsightProvider:", err.Error())
		return nil
	}

	decoded, err := hex.DecodeString(raw.RawTx)
	if err != nil {
		log.Println("Failed to decode response of GetTransaction in InsightProvider:", err.Error())
		return nil
	}

	tx, err := btcutil.NewTxFromBytes(decoded)
	if err != nil {
		log.Println("Failed to derive txn from response of GetTransaction in InsightProvider:", err.Error())
		return nil
	}
	return tx
}

func (p *InsightProvider) GetRawTransactionFromTxId(txidStr string) ([]byte, error) {
	txid, err := chainhash.NewHashFromStr(txidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse txidStr: %s", err.Error())
	}

	tx := p.GetTransaction(txid)
	if tx == nil {
		return nil, errors.New("GetTransaction returned nil")
	}

	var b bytes.Buffer
	wr := bufio.NewWriter(&b)
	err = tx.MsgTx().BtcEncode(wr, 0, wire.WitnessEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to encode the transaction: %s", err.Error())
	}
	err = wr.Flush()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to flush the buffer while encoding the transaction: %s", err.Error())
	}
	return b.Bytes(), nil
}
