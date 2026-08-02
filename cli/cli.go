// Package cli handles command-line interface execution, user inputs, and blockchain actions routing.
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

// CLI represents the command-line interface structure.
type CLI struct{}

// NewCLI initializes and returns a new CLI instance.
func NewCLI() *CLI {
	return &CLI{}
}

// printUsage displays available CLI commands and instructions to the user.
func (cli *CLI) printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  createblockchain -address <ADDRESS>   - Create a blockchain and send genesis reward")
	fmt.Println("  createwallet                          - Generates a new wallet address")
	fmt.Println("  getbalance -address <ADDRESS>         - Get balance of an address")
	fmt.Println("  printchain                            - Print all blocks of the blockchain")
	fmt.Println("  mine -miner <ADDRESS>                 - Mine a new block with pending mempool txs")
	fmt.Println("  send -from <FROM> -to <TO> -amount <AMOUNT> - Send coins from one address to another")
}

// validateArgs ensures that at least one argument is provided to the CLI.
func (cli *CLI) validateArgs() {
	if len(os.Args) < 2 {
		cli.printUsage()
		os.Exit(1)
	}
}

// createBlockchain initializes a new blockchain database and generates the genesis block.
func (cli *CLI) createBlockchain(address string) {
	bc := core.CreateBlockchain(address)
	defer bc.Db.Close()
	fmt.Println("Done! Genesis block created.")
}

// getBalance retrieves and prints the unspent coin balance for a specific address from the database.
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

// createWallet generates a new cryptographic wallet and prints its address.
func (cli *CLI) createWallet() {
	w := wallet.NewWallet()
	fmt.Printf("New Wallet Generated!\n")
	fmt.Printf("Address : %s\n", w.GetAddress())
}

// printChain iterates through and prints details of all blocks currently stored in the blockchain.
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

// send creates a new UTXO transaction and pushes it into the persistent mempool database.
func (cli *CLI) send(from, to string, amount int) {
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
	mempool := core.NewMempool(db)

	tx, err := bc.NewUTXOTransaction(from, to, amount)
	if err != nil {
		log.Fatalf("Transaction failed: %v", err)
	}

	mempool.Add(tx)
	fmt.Println("Success! Transaction added to mempool.")
}

// mine processes pending transactions from the persistent mempool database and mines a new block.
func (cli *CLI) mine(minerAddress string) {
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
	mempool := core.NewMempool(db)

	bc.MineBlock(mempool, minerAddress)
}

// Run parses command-line flags and routes execution to the appropriate CLI handler function.
func (cli *CLI) Run() {
	cli.validateArgs()

	createblockchainCmd := flag.NewFlagSet("createblockchain", flag.ExitOnError)
	getbalanceCmd := flag.NewFlagSet("getbalance", flag.ExitOnError)
	createwalletCmd := flag.NewFlagSet("createwallet", flag.ExitOnError)
	printchainCmd := flag.NewFlagSet("printchain", flag.ExitOnError)
	mineCmd := flag.NewFlagSet("mine", flag.ExitOnError)
	sendCmd := flag.NewFlagSet("send", flag.ExitOnError)

	createBlockchainAddress := createblockchainCmd.String("address", "", "The address to send genesis reward to")
	getBalanceAddress := getbalanceCmd.String("address", "", "The address to get balance for")
	mineMiner := mineCmd.String("miner", "", "Miner address to receive block reward")
	sendFrom := sendCmd.String("from", "", "Source wallet address")
	sendTo := sendCmd.String("to", "", "Destination wallet address")
	sendAmount := sendCmd.Int("amount", 0, "Amount to send")

	// Match and parse specific command flags
	switch os.Args[1] {
	case "createblockchain":
		_ = createblockchainCmd.Parse(os.Args[2:])
	case "getbalance":
		_ = getbalanceCmd.Parse(os.Args[2:])
	case "createwallet":
		_ = createwalletCmd.Parse(os.Args[2:])
	case "printchain":
		_ = printchainCmd.Parse(os.Args[2:])
	case "mine":
		_ = mineCmd.Parse(os.Args[2:])
	case "send":
		_ = sendCmd.Parse(os.Args[2:])
	default:
		cli.printUsage()
		os.Exit(1)
	}

	// Execute respective actions based on parsed flags
	if createblockchainCmd.Parsed() {
		if *createBlockchainAddress == "" {
			createblockchainCmd.Usage()
			os.Exit(1)
		}
		cli.createBlockchain(*createBlockchainAddress)
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

	if sendCmd.Parsed() {
		if *sendFrom == "" || *sendTo == "" || *sendAmount <= 0 {
			sendCmd.Usage()
			os.Exit(1)
		}
		cli.send(*sendFrom, *sendTo, *sendAmount)
	}
}
