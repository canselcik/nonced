package provider

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcutil"
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

func (p *InsightProvider) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	client := http.Client{
		Timeout: time.Duration(5 * time.Second),
	}

	url := fmt.Sprintf("%s/api/rawblock/%s", p.address, hash.String())
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to GetRawBlock in InsightProvider: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"got %d from InsightProvider for block %s", resp.StatusCode, hash.String())
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read response of GetRawBlock in InsightProvider: %s", err.Error())
	}

	var raw struct {
		RawBlock string `json:"rawblock"`
	}
	err = json.Unmarshal(body, &raw)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse response of GetRawBlock in InsightProvider: %s", err.Error())
	}

	decoded, err := hex.DecodeString(raw.RawBlock)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to decode response of GetRawBlock in InsightProvider: %s", err.Error())
	}

	block, err := btcutil.NewBlockFromBytes(decoded)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to derive block from response of GetRawBlock in InsightProvider: %s", err.Error())
	}
	return block.MsgBlock(), nil
}

func (p *InsightProvider) GetTransaction(txid *chainhash.Hash) (*btcutil.Tx, error) {
	client := http.Client{
		Timeout: time.Duration(5 * time.Second),
	}

	url := fmt.Sprintf("%s/api/rawtx/%s", p.address, txid.String())
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to GetTransaction in InsightProvider: %s", err.Error())
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"got resp code %d from InsightProvider for txn %s", resp.StatusCode, txid.String())
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read response of GetTransaction in InsightProvider: %s", err.Error())
	}

	var raw struct {
		RawTx string `json:"rawtx"`
	}
	err = json.Unmarshal(body, &raw)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse response of GetTransaction in InsightProvider: %s", err.Error())
	}

	decoded, err := hex.DecodeString(raw.RawTx)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to decode response of GetTransaction in InsightProvider: %s", err.Error())
	}

	tx, err := btcutil.NewTxFromBytes(decoded)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to derive txn from response of GetTransaction in InsightProvider: %s", err.Error())
	}
	return tx, nil
}

func (p *InsightProvider) GetRawTransactionFromTxId(txidStr string) ([]byte, error) {
	txid, err := chainhash.NewHashFromStr(txidStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse txidStr: %s", err.Error())
	}

	tx, err := p.GetTransaction(txid)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("GetTransaction returned nil")
	}

	return SerializeBitcoinMsgTx(tx.MsgTx())
}
