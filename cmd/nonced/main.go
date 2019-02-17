package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
	"github.com/canselcik/nonced/internal/provider"
	"github.com/canselcik/nonced/internal/realtime"
	"github.com/canselcik/nonced/internal/sighash"
	"github.com/canselcik/nonced/internal/storage"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
)

func ProcessErrMap(txid string, errMap map[int]error) (warnCount, errCount int) {
	for inputIdx, err := range errMap {
		switch err {
		case sighash.WarnWitnessSkip:
			warnCount++
		default:
			errCount++
			log.WithFields(log.Fields{
				"err":      err,
				"inputIdx": inputIdx,
				"tx":       txid,
			}).Warnln("Skipped input due to critical error")
		}
	}
	return
}

func QueryLocalHeight(c *cli.Context) error {
	var ds provider.DataProvider
	if c.GlobalBool("insight") {
		ds = provider.NewInsightProvider()
		log.Info("Using Insight as DataProvider")
	} else {
		ds = provider.NewLocalBitcoindRpcProvider()
	}

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

	var ds provider.DataProvider
	if c.GlobalBool("insight") {
		ds = provider.NewInsightProvider()
		log.Info("Using Insight as DataProvider")

	} else {
		ds = provider.NewLocalBitcoindRpcProvider()
	}

	solveBucket := sighash.NewSHPairBucket(ds)

	hash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return err
	}
	tx, err := ds.GetTransaction(hash)
	if err != nil {
		return err
	}
	if tx == nil {
		return fmt.Errorf("unable to find the transaction with id: %s", txid)
	}

	sigCount, errMap := solveBucket.AddTx(tx.MsgTx())
	_, _ = ProcessErrMap(txid, errMap)
	if sigCount < 2 {
		return fmt.Errorf("given transaction yielded fewer than 2 signatures")
	}

	solutions := solveBucket.Solve()
	log.Println("Extracted", len(solutions), "private key(s)")
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

	var ds provider.DataProvider
	if c.GlobalBool("insight") {
		ds = provider.NewInsightProvider()
		log.Info("Using Insight as DataProvider")
	} else {
		ds = provider.NewLocalBitcoindRpcProvider()
	}

	block, err := ds.GetBlock(id)
	if block == nil {
		return fmt.Errorf("unable to find the block with id %s due to error: %s", blockId, err.Error())
	}

	skipped, ok, parseErr := 0, 0, 0
	solveBucket := sighash.NewSHPairBucket(ds)
	for i, tx := range block.Transactions {
		if err != nil {
			log.WithFields(log.Fields{
				"txidx":     i,
				"blockhash": tx.TxHash(),
				"err":       err,
			}).Warn("Failed to serialize transaction")
			parseErr++
			continue
		}

		extracted, errMap := solveBucket.AddTx(tx)
		warnCount, errCount := ProcessErrMap(tx.TxHash().String(), errMap)
		if warnCount+errCount == 0 {
			ok++
		}
		skipped += warnCount
		log.WithFields(log.Fields{
			"txid":           tx.TxHash(),
			"yieldedSHPairs": extracted,
		}).Debugln("Done processing transaction")
	}

	log.WithFields(log.Fields{
		"hash":               blockId,
		"parseErrTxns":       parseErr,
		"skippedWitnessTxns": skipped,
		"okTxns":             ok,
		"txnCount":           len(block.Transactions),
		"yieldedSHPairs":     len(solveBucket.Pairs),
	}).Infoln("Done processing block")

	solutions := solveBucket.Solve()
	log.WithField("solutionCount", len(solutions)).Infoln("Done processing SHPairs")
	for i, priv := range solutions {
		serialized := priv.Serialize()
		log.Infof("\tHex Encoded Private Key %d: %s\n", i, hex.EncodeToString(serialized))
	}
	return nil
}

func NonceReuseRealtime(c *cli.Context) error {
	var ds provider.DataProvider

	// Init the provider
	if c.GlobalBool("insight") {
		ds = provider.NewInsightProvider()
		log.Info("Using Insight as DataProvider")
	} else {
		ds = provider.NewLocalBitcoindRpcProvider()
	}

	// Init storage
	var db storage.Storage
	if c.Bool("db") {
		st, err := storage.NewPostgresStorage("localhost", 5432,
			"postgres", "postgres", "postgres")
		if err != nil {
			return err
		}
		log.Infof("DB enabled!")
		db = st
	} else {
		db = storage.NewNullStorage()
	}

	// Init the realtime streamer
	addr := c.String("connstring")
	if len(addr) == 0 {
		addr = "tcp://127.0.0.1:28333"
	}
	streamer, err := realtime.NewBtcdZmqStreamer(addr, []string{"rawtx"})
	if err != nil {
		return err
	}
	defer streamer.Close()
	log.Infof("Connected to ZMQ at %s, subscribed to 'rawtx'", addr)

	// Stream
	return streamer.Stream(func(msgType string, msgBody []byte) {
		switch msgType {
		case "rawtx":
			tx, err := btcutil.NewTxFromBytes(msgBody)
			if err != nil {
				log.WithFields(log.Fields{
					"err": err,
					"tx":  msgBody,
				}).Errorln("Failed to parse txn")
				return
			}

			txid := tx.Hash().String()
			solveBucket := sighash.NewSHPairBucket(ds)
			sigCount, errMap := solveBucket.AddTx(tx.MsgTx())
			for inputIdx, err := range errMap {
				switch err {
				case sighash.WarnWitnessSkip:
					log.WithFields(log.Fields{
						"err":      err,
						"inputIdx": inputIdx,
						"tx":       txid,
					}).Warnln("Skipped input due to txwitness")
				default:
					log.WithFields(log.Fields{
						"err":      err,
						"inputIdx": inputIdx,
						"tx":       txid,
					}).Warnln("Skipped input due to critical error")
				}
			}

			for _, pair := range solveBucket.Pairs {
				err := db.PutEntry(txid, pair.PublicKey, pair.Z, pair.R.Bytes(), pair.S.Bytes())
				if err != nil {
					log.Fatalln(err.Error())
				}
			}

			if sigCount >= 2 {
				solutions := solveBucket.Solve()
				log.Println("Extracted", len(solutions), "private key(s)")
				for _, priv := range solutions {
					serialized := priv.Serialize()
					log.WithField("hexEncoded", hex.EncodeToString(serialized)).
						Info("Found private key")
				}
			}

		case "rawblock":
			// Just display the block -- we don't subscribe
			// to this topic anymore anyway.
			block, err := btcutil.NewBlockFromBytes(msgBody)
			if err != nil {
				log.WithFields(log.Fields{
					"err":   err,
					"block": msgBody,
				}).Errorln("Failed to parse block")
				return
			}
			log.WithFields(log.Fields{
				"blockHash": block.Hash().String(),
			}).Infoln("New block")
		default:
			log.Fatalf("Receive message with unknown type from ZMQ: %s", msgType)
		}
	})
}

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "insight",
			Usage: "specify to use insight to fetch transactions and blocks",
		},
		cli.StringFlag{
			Name: "btcd",
			Usage: "specify the bitcoind instance with which nonced will interact",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "query",
			Usage: "custom queries for diagnostic usage",
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
					Name:  "stream",
					Usage: "streams from bitcoind via ZMQ and performs realtime analysis",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "connstring",
							Usage: "connstring for the ZMQ publisher source",
						},
						cli.BoolFlag{
							Name:  "db",
							Usage: "use db",
						},
					},
					Action: NonceReuseRealtime,
				},
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
