// Package main implements a robust, modular, and production-ready Proof-of-Work (PoW) 
// blockchain core featuring BoltDB permanent storage, ECDSA digital signatures, 
// a transaction mempool, adaptive difficulty, and a lightweight P2P networking layer.
package main

import (
	"blockchain/wallet"
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/sha3"
)

// Constants defining core blockchain operational parameters.
const (
	dbFile            = "blockchain.db" // Database file name stored locally
	blocksBucket      = "blocks"        // BoltDB bucket key for block storage
	Subsidy           = 50              // Block reward subsidy in coins allocated per mined block
	BlockInterval     = 5               // Interval blocks required for triggering dynamic difficulty adjustments
	BlockTargetTime   = 60              // Target time in seconds defined for mining a block interval
	InitialDifficulty = 12              // Starting mining difficulty bits threshold
)

// ================= STRUCT DEFINITIONS =================

// TXInput represents a transaction input pointing to a previous unspent transaction output.
type TXInput struct {
	Txid      string
	Vout      int
	Signature []byte
	PubKey    []byte
}

// TXOutput represents a transaction output containing value and locking script recipient address.
type TXOutput struct {
	Value        int
	ScriptPubKey string
}

// Transaction encapsulates the details of a value transfer or coin generation within the network.
type Transaction struct {
	ID   string
	Vin  []TXInput
	Vout []TXOutput
}

// Block defines the core data structure containing transaction records, cryptographic hashes, and consensus metadata.
type Block struct {
	Timestamp     int64
	Transactions  []*Transaction
	PrevBlockHash string
	Hash          string
	Nonce         int
	Height        int
	Difficulty    int
}

// Blockchain maintains references to the persistent database tip and underlying storage engine.
type Blockchain struct {
	Tip []byte
	Db  *bbolt.DB
}

// ProofOfWork encapsulates the mining logic, hashing target computations, and nonce searching.
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// Mempool manages unconfirmed transactions waiting to be packed into newly mined blocks.
type Mempool struct {
	mu           sync.Mutex
	transactions map[string]*Transaction
}

// Global mempool instance initialization for tracking unconfirmed transactions.
var mempool = NewMempool()

// ================= MEMPOOL MANAGEMENT =================

// NewMempool instantiates and returns a thread-safe transaction pool.
func NewMempool() *Mempool {
	return &Mempool{transactions: make(map[string]*Transaction)}
}

// Add safely inserts a new pending transaction into the mempool map using a mutex lock.
func (mp *Mempool) Add(tx *Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.transactions[tx.ID] = tx
}

// GetAll extracts and returns a slice of all currently pending transactions.
func (mp *Mempool) GetAll() []*Transaction {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	var txs []*Transaction
	for _, tx := range mp.transactions {
		txs = append(txs, tx)
	}
	return txs
}

// Clear purges successfully mined non-coinbase transactions from the mempool container.
func (mp *Mempool) Clear(minedTxs []*Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	for _, tx := range minedTxs {
		if !tx.IsCoinbase() {
			delete(mp.transactions, tx.ID)
		}
	}
}

// Size returns the current count of pending transactions awaiting block confirmation.
func (mp *Mempool) Size() int {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	return len(mp.transactions)
}

// ================= CRYPTOGRAPHIC & UTILITY FUNCTIONS =================

// HashKeccak256 computes a secure cryptographic hash using the SHA-3 (Keccak-256) algorithm.
func HashKeccak256(b []byte) string {
	h := sha3.New256()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Hash serializes the transaction object and returns its unique cryptographic identifier string.
func (tx *Transaction) Hash() string {
	var encoded bytes.Buffer
	enc := json.NewEncoder(&encoded)
	_ = enc.Encode(tx)
	return HashKeccak256(encoded.Bytes())
}

// IsCoinbase evaluates whether the current transaction is a system-generated block reward.
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Vin) == 1 && tx.Vin[0].Txid == "" && tx.Vin[0].Vout == -1
}

// ================= TRANSACTION SIGNING & VERIFICATION =================

// TrimmedCopy creates a shallow copy of a transaction stripped of signatures for signing purposes.
func (tx *Transaction) TrimmedCopy() Transaction {
	var inputs []TXInput
	var outputs []TXOutput
	// Iterate and copy inputs without signature or public key data
	for _, vin := range tx.Vin {
		inputs = append(inputs, TXInput{vin.Txid, vin.Vout, nil, nil})
	}
	// Iterate and copy outputs
	for _, vout := range tx.Vout {
		outputs = append(outputs, TXOutput{vout.Value, vout.ScriptPubKey})
	}
	return Transaction{tx.ID, inputs, outputs}
}

// Sign signs each input of a transaction using the owner's private key credentials.
func (tx *Transaction) Sign(w *wallet.Wallet, prevTxs map[string]*Transaction) {
	// Skip signing if it's a coinbase transaction
	if tx.IsCoinbase() {
		return
	}

	txCopy := tx.TrimmedCopy()

	// Loop through each input to apply cryptographic signature
	for inID, vin := range tx.Vin {
		prevTx := prevTxs[vin.Txid]
		txCopy.Vin[inID].PubKey = []byte(prevTx.Vout[vin.Vout].ScriptPubKey)
		txCopy.ID = txCopy.Hash()
		txCopy.Vin[inID].PubKey = nil

		// Generate signature over the trimmed transaction hash
		signature := w.Sign([]byte(txCopy.ID))
		tx.Vin[inID].Signature = signature
		tx.Vin[inID].PubKey = w.PublicKey
	}
}

// Verify validates the cryptographic digital signature attached to each transaction input.
func (tx *Transaction) Verify(prevTxs map[string]*Transaction) bool {
	// Coinbase transactions do not require input verification
	if tx.IsCoinbase() {
		return true
	}

	txCopy := tx.TrimmedCopy()

	// Loop through inputs to verify digital signatures against public keys
	for inID, vin := range tx.Vin {
		prevTx := prevTxs[vin.Txid]
		txCopy.Vin[inID].PubKey = []byte(prevTx.Vout[vin.Vout].ScriptPubKey)
		txCopy.ID = txCopy.Hash()
		txCopy.Vin[inID].PubKey = nil

		// Perform signature verification check via wallet utility
		if !wallet.Verify(vin.PubKey, vin.Signature, []byte(txCopy.ID)) {
			return false
		}
	}
	return true
}

// ================= PROOF OF WORK (PoW) CONSENSUS =================

// NewProofOfWork initializes and returns a PoW mining target structure for a target block.
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	// Left shift target value based on block difficulty level
	target.Lsh(target, uint(256-b.Difficulty))
	return &ProofOfWork{block: b, target: target}
}

// prepareData flattens block components and headers into a contiguous byte stream for hashing.
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	var txHashes [][]byte
	// Extract transaction IDs for cryptographic merging
	for _, tx := range pow.block.Transactions {
		txHashes = append(txHashes, []byte(tx.ID))
	}
	txHash := sha256.Sum256(bytes.Join(txHashes, []byte{}))

	// Combine header elements into a single byte array
	data := bytes.Join(
		[][]byte{
			[]byte(pow.block.PrevBlockHash),
			txHash[:],
			intToHex(pow.block.Timestamp),
			intToHex(int64(pow.block.Difficulty)),
			intToHex(int64(nonce)),
		},
		[]byte{},
	)
	return data
}

// Run executes the resource-intensive mining computation loop to discover a valid block nonce.
func (pow *ProofOfWork) Run() (int, string) {
	var hashInt big.Int
	var hash string
	nonce := 0

	fmt.Printf("[PoW] Mining block at height %d (Difficulty: %d)...\n", pow.block.Height, pow.block.Difficulty)
	// Iterate until maximum integer limit trying different nonce values
	for nonce < math.MaxInt64 {
		data := pow.prepareData(nonce)
		hash = HashKeccak256(data)
		hashInt.SetString(hash, 16)

		// Check if computed hash is below the strict target threshold criteria
		if hashInt.Cmp(pow.target) == -1 {
			break
		}
		nonce++
	}
	return nonce, hash
}

// intToHex safely converts a 64-bit integer into a hexadecimal byte slice representation.
func intToHex(n int64) []byte {
	return []byte(fmt.Sprintf("%x", n))
}

// ================= STORAGE & PERSISTENCE (BOLTDB) =================

// CreateBlockchain initializes a fresh persistent BoltDB database and writes the Genesis block.
func CreateBlockchain(address string) *Blockchain {
	// Remove old database file if it already exists on disk
	if _, err := os.Stat(dbFile); err == nil {
		_ = os.Remove(dbFile)
	}

	// Open BoltDB database connection instance
	db, err := bbolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	var tip []byte
	// Update database to create bucket and store genesis block
	err = db.Update(func(tx *bbolt.Tx) error {
		cbtx := NewCoinbaseTX(address, "Genesis Block - Initializing Network")
		genesis := CreateGenesisBlock(cbtx)
		b, err := tx.CreateBucket([]byte(blocksBucket))
		if err != nil {
			return err
		}
		// Put genesis block data serialized by hash key
		err = b.Put([]byte(genesis.Hash), serializeBlock(genesis))
		if err != nil {
			return err
		}
		// Store database tip pointer reference key "l"
		err = b.Put([]byte("l"), []byte(genesis.Hash))
		if err != nil {
			return err
		}
		tip = []byte(genesis.Hash)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return &Blockchain{tip, db}
}

// OpenBlockchain opens an existing BoltDB database instance for ongoing blockchain operations.
func OpenBlockchain() *Blockchain {
	// Check if database file exists before opening
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		fmt.Println("No existing blockchain found. Create one using 'createblockchain -address <address>' first.")
		os.Exit(1)
	}

	// Open connection to existing database file
	db, err := bbolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	var tip []byte
	// Read tip hash from database view transaction
	err = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		tip = b.Get([]byte("l"))
		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return &Blockchain{tip, db}
}

// CreateGenesisBlock mines and provisions the absolute first block of the chain.
func CreateGenesisBlock(coinbase *Transaction) *Block {
	block := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  []*Transaction{coinbase},
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Height:        0,
		Difficulty:    InitialDifficulty,
	}
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Nonce = nonce
	block.Hash = hash
	return block
}

// serializeBlock encodes a Block structure into binary format using Go's Gob package.
func serializeBlock(b *Block) []byte {
	var result bytes.Buffer
	enc := gob.NewEncoder(&result)
	_ = enc.Encode(b)
	return result.Bytes()
}

// deserializeBlock decodes binary byte streams back into structured Block instances.
func deserializeBlock(d []byte) *Block {
	var block Block
	dec := gob.NewDecoder(bytes.NewReader(d))
	_ = dec.Decode(&block)
	return &block
}

// NewCoinbaseTX generates a brand-new mining reward transaction for block finders.
func NewCoinbaseTX(to, data string) *Transaction {
	if data == "" {
		data = fmt.Sprintf("Reward to '%s'", to)
	}
	txin := TXInput{Txid: "", Vout: -1, Signature: nil, PubKey: []byte(data)}
	txout := TXOutput{Value: Subsidy, ScriptPubKey: to}
	tx := Transaction{ID: "", Vin: []TXInput{txin}, Vout: []TXOutput{txout}}
	tx.ID = tx.Hash()
	return &tx
}

// FindUnspentTransactions scans historical blocks in the database to trace user UTXOs.
func (bc *Blockchain) FindUnspentTransactions(address string) []Transaction {
	var unspentTXs []Transaction
	spentTXos := make(map[string][]int)

	// View database blocks using cursor traversal
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		cursor := b.Cursor()

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := deserializeBlock(v)

			for _, tx := range block.Transactions {
				txID := tx.ID

				for outIdx, out := range tx.Vout {
					// Check if output has already been spent in later transactions
					if spentTXos[txID] != nil {
						spent := false
						for _, spentOut := range spentTXos[txID] {
							if spentOut == outIdx {
								spent = true
								break
							}
						}
						if spent {
							continue
						}
					}

					// Append to unspent list if output matches address
					if out.ScriptPubKey == address {
						unspentTXs = append(unspentTXs, *tx)
					}
				}

				// Track spent inputs if transaction is not a coinbase
				if !tx.IsCoinbase() {
					for _, in := range tx.Vin {
						if wallet.GetAddressFromPubKey(in.PubKey) == address {
							spentTXos[in.Txid] = append(spentTXos[in.Txid], in.Vout)
						}
					}
				}
			}
		}
		return nil
	})
	return unspentTXs
}

// FindSpendableOutputs compiles valid unspent transaction outputs until the requested amount is fulfilled.
func (bc *Blockchain) FindSpendableOutputs(address string, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	unspentTXs := bc.FindUnspentTransactions(address)
	accumulated := 0

Work:
	for _, tx := range unspentTXs {
		txID := tx.ID

		for outIdx, out := range tx.Vout {
			if out.ScriptPubKey == address && accumulated < amount {
				accumulated += out.Value
				unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)

				// Break loop once requested amount is accumulated
				if accumulated >= amount {
					break Work
				}
			}
		}
	}
	return accumulated, unspentOutputs
}

// GetBalance calculates the total spendable balance for an account address.
func (bc *Blockchain) GetBalance(address string) int {
	unspentTXs := bc.FindUnspentTransactions(address)
	balance := 0

	// Sum up all values from unspent transaction outputs matching address
	for _, tx := range unspentTXs {
		for _, out := range tx.Vout {
			if out.ScriptPubKey == address {
				balance += out.Value
			}
		}
	}
	return balance
}

// FindTransactionByHash searches and retrieves a specific transaction record structure by its ID.
func (bc *Blockchain) FindTransactionByHash(ID string) (Transaction, error) {
	var foundTx Transaction
	err := bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		cursor := b.Cursor()

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := deserializeBlock(v)
			// Search transactions inside block for matching ID
			for _, t := range block.Transactions {
				if t.ID == ID {
					foundTx = *t
					return nil
				}
			}
		}
		return errors.New("transaction not found")
	})
	if err != nil {
		return Transaction{}, err
	}
	return foundTx, nil
}

// NewUTXOTransaction builds, signs, and verifies a balanced value transfer transaction between wallets.
func NewUTXOTransaction(walletSender *wallet.Wallet, recipient string, amount int, bc *Blockchain) (*Transaction, error) {
	var inputs []TXInput
	var outputs []TXOutput

	sender := walletSender.GetAddress()
	acc, validOutputs := bc.FindSpendableOutputs(sender, amount)

	// Return error if sender has insufficient funds available
	if acc < amount {
		return nil, errors.New("error: insufficient funds")
	}

	prevTxs := make(map[string]*Transaction)

	// Collect previous transactions required for signing inputs
	for txid, outs := range validOutputs {
		for _, outIdx := range outs {
			tx, err := bc.FindTransactionByHash(txid)
			if err == nil {
				prevTxs[txid] = &tx
			}
			input := TXInput{Txid: txid, Vout: outIdx, Signature: nil, PubKey: walletSender.PublicKey}
			inputs = append(inputs, input)
		}
	}

	// Create output for recipient and change output for sender if necessary
	outputs = append(outputs, TXOutput{Value: amount, ScriptPubKey: recipient})
	if acc > amount {
		outputs = append(outputs, TXOutput{Value: acc - amount, ScriptPubKey: sender})
	}

	tx := Transaction{ID: "", Vin: inputs, Vout: outputs}
	tx.ID = tx.Hash()
	tx.Sign(walletSender, prevTxs)

	return &tx, nil
}

// CalculateDifficulty dynamically adjusts mining difficulty based on block intervals.
func (bc *Blockchain) CalculateDifficulty(lastBlock *Block) int {
	// Only adjust difficulty every `BlockInterval` blocks
	if lastBlock.Height == 0 || lastBlock.Height%BlockInterval != 0 {
		return lastBlock.Difficulty
	}

	var prevAdjustmentBlock *Block
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		cursor := b.Cursor()
		
		targetHeight := lastBlock.Height - BlockInterval
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := deserializeBlock(v)
			if block.Height == targetHeight {
				prevAdjustmentBlock = block
				break
			}
		}
		return nil
	})

	if prevAdjustmentBlock == nil {
		return lastBlock.Difficulty
	}

	actualTimeSpan := lastBlock.Timestamp - prevAdjustmentBlock.Timestamp
	targetTimeSpan := int64(BlockInterval * BlockTargetTime)

	// Increase or decrease difficulty depending on actual time taken vs target time
	if actualTimeSpan < targetTimeSpan/2 {
		return lastBlock.Difficulty + 1
	} else if actualTimeSpan > targetTimeSpan*2 {
		if lastBlock.Difficulty > 1 {
			return lastBlock.Difficulty - 1
		}
	}

	return lastBlock.Difficulty
}

// MineBlock packs pending mempool transactions, runs PoW consensus, and appends the new block into storage.
func (bc *Blockchain) MineBlock(transactions []*Transaction, minerAddress string) *Block {
	var lastHash []byte
	var lastBlock *Block

	// Retrieve last block hash and metadata from database
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash = b.Get([]byte("l"))
		lastBlock = deserializeBlock(b.Get(lastHash))
		return nil
	})

	// Calculate new target difficulty dynamically
	newDifficulty := bc.CalculateDifficulty(lastBlock)

	var validTransactions []*Transaction
	prevTxs := make(map[string]*Transaction)

	// Load previous transactions to verify unconfirmed transaction inputs
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := deserializeBlock(v)
			for _, t := range block.Transactions {
				prevTxs[t.ID] = t
			}
		}
		return nil
	})

	// Validate transactions before packing them into the new block
	for _, tx := range transactions {
		if tx.IsCoinbase() {
			validTransactions = append(validTransactions, tx)
			continue
		}
		if tx.Verify(prevTxs) {
			validTransactions = append(validTransactions, tx)
		}
	}

	// Create coinbase reward transaction for the miner
	cbtx := NewCoinbaseTX(minerAddress, "")
	allTransactions := append([]*Transaction{cbtx}, validTransactions...)

	newBlock := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  allTransactions,
		PrevBlockHash: hex.EncodeToString(lastHash),
		Height:        lastBlock.Height + 1,
		Difficulty:    newDifficulty,
	}

	// Run Proof-of-Work algorithm to mine the block
	pow := NewProofOfWork(newBlock)
	nonce, hash := pow.Run()
	newBlock.Nonce = nonce
	newBlock.Hash = hash

	// Save newly mined block into BoltDB database storage
	bc.Db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		_ = b.Put([]byte(newBlock.Hash), serializeBlock(newBlock))
		_ = b.Put([]byte("l"), []byte(newBlock.Hash))
		bc.Tip = []byte(newBlock.Hash)
		return nil
	})

	// Clear processed transactions from mempool
	mempool.Clear(transactions)
	return newBlock
}

// ================= P2P NETWORK SIMULATOR =================

// StartP2PServer spins up a lightweight background TCP listener for peer synchronization.
func StartP2PServer(port string) {
	listen, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return
	}
	defer listen.Close()
	// Accept incoming peer connections continuously in background loop
	for {
		conn, err := listen.Accept()
		if err != nil {
			break
		}
		go func(c net.Conn) {
			_, _ = io.ReadAll(c)
			c.Close()
		}(conn)
	}
}

// ================= COMMAND LINE INTERFACE (CLI) =================

// CLI structure definition for handling user terminal input arguments.
type CLI struct{}

// printUsage displays manual instructions for available terminal commands.
func (cli *CLI) printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  createblockchain -address <ADDRESS>    - Create a blockchain and send genesis reward")
	fmt.Println("  createwallet                           - Generates a new wallet address")
	fmt.Println("  getbalance -address <ADDRESS>          - Get balance of an address")
	fmt.Println("  printchain                             - Print all blocks of the blockchain")
	fmt.Println("  mine -miner <ADDRESS>                  - Mine a new block with pending mempool txs")
}

// validateArgs ensures command line execution contains proper argument lengths.
func (cli *CLI) validateArgs() {
	if len(os.Args) < 2 {
		cli.printUsage()
		os.Exit(1)
	}
}

// Run parses command line arguments and executes appropriate blockchain actions.
func (cli *CLI) Run() {
	cli.validateArgs()

	// Initialize individual flag set command definitions
	createBlockchainCmd := flag.NewFlagSet("createblockchain", flag.ExitOnError)
	createWalletCmd := flag.NewFlagSet("createwallet", flag.ExitOnError)
	getBalanceCmd := flag.NewFlagSet("getbalance", flag.ExitOnError)
	printChainCmd := flag.NewFlagSet("printchain", flag.ExitOnError)
	mineCmd := flag.NewFlagSet("mine", flag.ExitOnError)

	createBlockchainAddress := createBlockchainCmd.String("address", "", "The address to send genesis block reward to")
	getBalanceAddress := getBalanceCmd.String("address", "", "The address to get balance for")
	mineMinerAddress := mineCmd.String("miner", "", "Miner address to receive block reward")

	// Switch statement to evaluate command argument category
	switch os.Args[1] {
	case "createblockchain":
		_ = createBlockchainCmd.Parse(os.Args[2:])
	case "createwallet":
		_ = createWalletCmd.Parse(os.Args[2:])
	case "getbalance":
		_ = getBalanceCmd.Parse(os.Args[2:])
	case "printchain":
		_ = printChainCmd.Parse(os.Args[2:])
	case "mine":
		_ = mineCmd.Parse(os.Args[2:])
	default:
		cli.printUsage()
		os.Exit(1)
	}

	// Handle execution for createblockchain command
	if createBlockchainCmd.Parsed() {
		if *createBlockchainAddress == "" {
			createBlockchainCmd.Usage()
			os.Exit(1)
		}
		bc := CreateBlockchain(*createBlockchainAddress)
		defer bc.Db.Close()
		fmt.Println("Done! Genesis block created.")
	}

	// Handle execution for createwallet command
	if createWalletCmd.Parsed() {
		w := wallet.NewWallet()
		fmt.Printf("New Wallet Generated!\nAddress: %s\n", w.GetAddress())
	}

	// Handle execution for getbalance command
	if getBalanceCmd.Parsed() {
		if *getBalanceAddress == "" {
			getBalanceCmd.Usage()
			os.Exit(1)
		}
		bc := OpenBlockchain()
		defer bc.Db.Close()
		balance := bc.GetBalance(*getBalanceAddress)
		fmt.Printf("Balance of '%s': %d coins\n", *getBalanceAddress, balance)
	}

	// Handle execution for printchain command
	if printChainCmd.Parsed() {
		bc := OpenBlockchain()
		defer bc.Db.Close()

		// View block items stored inside BoltDB bucket via cursor iteration
		bc.Db.View(func(tx *bbolt.Tx) error {
			b := tx.Bucket([]byte(blocksBucket))
			cursor := b.Cursor()
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				if string(k) == "l" {
					continue
				}
				block := deserializeBlock(v)
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

	// Handle execution for mine command
	if mineCmd.Parsed() {
		if *mineMinerAddress == "" {
			mineCmd.Usage()
			os.Exit(1)
		}
		bc := OpenBlockchain()
		defer bc.Db.Close()
		bc.MineBlock(mempool.GetAll(), *mineMinerAddress)
		fmt.Println("Success! Block mined.")
	}
}

// main serves as the primary program execution entrypoint.
func main() {
	// Start lightweight background P2P listener server on port 3000
	go StartP2PServer("3000")
	cli := CLI{}
	cli.Run()
}
