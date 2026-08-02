package cli

import (
	"flag"
	"fmt"
	"log"
	"mychain/core"
	"mychain/wallet"
	"os"

	"go.etcd.io/bbolt"
)

type CLI struct{}

func NewCLI() *CLI {
	return &CLI{}
}

func (cli *CLI) printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  createwallet                   - Generates a new wallet address")
	fmt.Println("  getbalance -address <ADDRESS>  - Gets balance of a specified address")
	fmt.Println("  printchain                     - Prints all the blocks of the blockchain")
	fmt.Println("  mine -miner <ADDRESS>          - Mine a new block")
}

func (cli *CLI) validateArgs() {
	if len(os.Args) < 2 {
		cli.printUsage()
		os.Exit(1)
	}
}

func (cli *CLI) getBalance(address string) {
	db, err := bbolt.Open("blockchain.db", 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	var tip []byte
	db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		tip = b.Get([]byte("l"))
		return nil
	})

	bc := &core.Blockchain{Tip: tip, Db: db}
	balance := bc.GetBalance(address)
	fmt.Printf("Balance of '%s': %d coins\n", address, balance)
}

func (cli *CLI) createWallet() {
	w := wallet.NewWallet()
	fmt.Printf("New Wallet Generated!\n")
	fmt.Printf("Address : %s\n", w.GetAddress())
}

func (cli *CLI) printChain() {
	db, err := bbolt.Open("blockchain.db", 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := core.DeserializeBlock(v)
			fmt.Printf("Block Height : %d\n", block.Height)
			fmt.Printf("Difficulty   : %d\n", block.Difficulty)
			fmt.Printf("Prev. Hash   : %s\n", block.PrevBlockHash)
			fmt.Printf("Block Hash   : %s\n", block.Hash)
			fmt.Printf("Nonce        : %d\n", block.Nonce)
			fmt.Printf("Tx Count     : %d\n", len(block.Transactions))
			fmt.Println("--------------------------------------------------")
		}
		return nil
	})
}

func (cli *CLI) mine(minerAddress string) {
	db, err := bbolt.Open("blockchain.db", 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	var tip []byte
	db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		tip = b.Get([]byte("l"))
		return nil
	})

	bc := &core.Blockchain{Tip: tip, Db: db}
	defer db.Close()

	fmt.Println("Mining new block...")
	// Untuk saat ini kita tambahkan block kosong / coinbase reward dulu
	bc.MineBlock([]*core.Transaction{}, minerAddress)
	fmt.Println("Success! Block mined.")
}

func (cli *CLI) Run() {
	cli.validateArgs()

	getbalanceCmd := flag.NewFlagSet("getbalance", flag.ExitOnError)
	createwalletCmd := flag.NewFlagSet("createwallet", flag.ExitOnError)
	printchainCmd := flag.NewFlagSet("printchain", flag.ExitOnError)
	mineCmd := flag.NewFlagSet("mine", flag.ExitOnError)

	getBalanceAddress := getbalanceCmd.String("address", "", "The address to get balance for")
	mineMiner := mineCmd.String("miner", "", "Miner address to receive block reward")

	switch os.Args[1] {
	case "getbalance":
		_ = getbalanceCmd.Parse(os.Args[2:])
	case "createwallet":
		_ = createwalletCmd.Parse(os.Args[2:])
	case "printchain":
		_ = printchainCmd.Parse(os.Args[2:])
	case "mine":
		_ = mineCmd.Parse(os.Args[2:])
	default:
		cli.printUsage()
		os.Exit(1)
	}

	if getbalanceCmd.Parsed() {
		if *getBalanceAddress == "" {
			getbalanceCmd.Usage()
			os.Exit(1)
		}
		cli.getBalance(*getBalanceAddress)
	}

	if createwalletCmd.Parsed() {
		cli.createWallet()
	}

	if printchainCmd.Parsed() {
		cli.printChain()
	}

	if mineCmd.Parsed() {
		if *mineMiner == "" {
			mineCmd.Usage()
			os.Exit(1)
		}
		cli.mine(*mineMiner)
	}
}
