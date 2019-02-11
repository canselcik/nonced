package main

import (
	"encoding/hex"
	"fmt"
	"github.com/canselcik/nonced/internal/provider"
	"github.com/canselcik/nonced/internal/sighash"
	"log"
	"os"

	"github.com/urfave/cli"
)

func QueryLocalHeight(c *cli.Context) error {
	ds, _ := provider.NewLocalBitcoindRpcProvider().(*provider.BtcdProvider)
	height, err := ds.GetBlockCount()
	if err != nil {
		return err
	}

	log.Println("Height:", height)
	return nil
}

func NonceReuseFromTx(c *cli.Context) error {
	txid := c.String("id")
	if len(txid) == 0 {
		return fmt.Errorf("--id parameter is required")
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
	fmt.Println("Extracted", len(solutions), "private key(s)")
	for i, priv := range solutions {
		serialized := priv.Serialize()
		fmt.Printf("Hex Encoded Private Key %d: %s\n", i, hex.EncodeToString(serialized))
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
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
