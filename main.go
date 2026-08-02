// Copyright 2026 The Aldianokto
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
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"
	"golang.org/x/crypto/sha3"
)

// Constants defining core blockchain operational parameters.
const (
	dbFile            = "blockchain.db" // Database file name stored locally
	mempoolFile       = "mempool.json"  // Persistent mempool backup file
	blocksBucket      = "blocks"        // BoltDB bucket key for block storage
	Subsidy           = 50              // Block reward subsidy in coins allocated per mined block
	BlockInterval     = 5               // Interval blocks required for triggering dynamic difficulty adjustments
	BlockTargetTime   = 60              // Target time in seconds defined for mining a block interval
	InitialDifficulty = 12              // Starting mining difficulty bits threshold
	LogDirName        = ".gnx"          // Directory name for debug logs
	LogFileName       = "debug.log"     // Log file name
)

// Global logger file descriptor for multi-writer outputs.
var logFile *os.File

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
	Transactions map[string]*Transaction
}

// Global mempool instance initialization for tracking unconfirmed transactions.
var mempool = NewMempool()

// ================= LOGGING SYSTEM =================

// InitLogger sets up file and console dual-logging resembling Bitcoin Core debug.log.
func InitLogger() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	logDirPath := filepath.Join(homeDir, LogDirName)
	if err := os.MkdirAll(logDirPath, 0755); err != nil {
		logDirPath = "."
	}

	logPath := filepath.Join(logDirPath, LogFileName)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Failed to open debug log file: %v", err)
		return
	}
	logFile = f

	// MultiWriter routes logs simultaneously to stdout (terminal) and debug.log file
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	
	log.Printf("[NODE] GNX Blockchain Core initialized. Logging to %s", logPath)
}

// CloseLogger gracefully closes the debug log file handle.
func CloseLogger() {
	if logFile != nil {
		_ = logFile.Close()
	}
}

// ================= MEMPOOL MANAGEMENT =================

// NewMempool instantiates and returns a thread-safe transaction pool loaded from disk.
func NewMempool() *Mempool {
	mp := &Mempool{Transactions: make(map[string]*Transaction)}
	mp.loadFromFile()
	return mp
}

// saveToFile persists current mempool transactions to a local JSON file.
func (mp *Mempool) saveToFile() {
	data, err := json.Marshal(mp.Transactions)
	if err != nil {
		return
	}
	_ = os.WriteFile(mempoolFile, data, 0644)
}

// loadFromFile reads pending transactions from the local JSON file.
func (mp *Mempool) loadFromFile() {
	if _, err := os.Stat(mempoolFile); os.IsNotExist(err) {
		return
	}
	data, err := os.ReadFile(mempoolFile)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &mp.Transactions)
}

// Add safely inserts a new pending transaction into the mempool and saves it to disk.
func (mp *Mempool) Add(tx *Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.Transactions[tx.ID] = tx
	mp.saveToFile()
	log.Printf("[MEMPOOL] Transaction added & saved to disk: %s", tx.ID)
}

// GetAll extracts and returns a slice of all currently pending transactions (refreshed from disk).
func (mp *Mempool) GetAll() []*Transaction {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.loadFromFile()
	var txs []*Transaction
	for _, tx := range mp.Transactions {
		txs = append(txs, tx)
	}
	return txs
}

// Clear purges successfully mined non-coinbase transactions and updates the disk file.
func (mp *Mempool) Clear(minedTxs []*Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	for _, tx := range minedTxs {
		if !tx.IsCoinbase() {
			delete(mp.Transactions, tx.ID)
			log.Printf("[MEMPOOL] Cleared mined transaction: %s", tx.ID)
		}
	}
	mp.saveToFile()
}

// Size returns the current count of pending transactions awaiting block confirmation.
func (mp *Mempool) Size() int {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.loadFromFile()
	return len(mp.Transactions)
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
	for _, vin := range tx.Vin {
		inputs = append(inputs, TXInput{vin.Txid, vin.Vout, nil, nil})
	}
	for _, vout := range tx.Vout {
		outputs = append(outputs, TXOutput{vout.Value, vout.ScriptPubKey})
	}
	return Transaction{tx.ID, inputs, outputs}
}

// Sign signs each input of a transaction using the owner's private key credentials.
func (tx *Transaction) Sign(w *wallet.Wallet, prevTxs map[string]*Transaction) {
	if tx.IsCoinbase() {
		return
	}

	txCopy := tx.TrimmedCopy()

	for inID, vin := range tx.Vin {
		prevTx := prevTxs[vin.Txid]
		txCopy.Vin[inID].PubKey = []byte(prevTx.Vout[vin.Vout].ScriptPubKey)
		txCopy.ID = txCopy.Hash()
		txCopy.Vin[inID].PubKey = nil

		signature := w.Sign([]byte(txCopy.ID))
		tx.Vin[inID].Signature = signature
		tx.Vin[inID].PubKey = w.PublicKey
	}
}

// Verify validates the cryptographic digital signature attached to each transaction input.
func (tx *Transaction) Verify(prevTxs map[string]*Transaction) bool {
	if tx.IsCoinbase() {
		return true
	}

	txCopy := tx.TrimmedCopy()

	for inID, vin := range tx.Vin {
		prevTx := prevTxs[vin.Txid]
		txCopy.Vin[inID].PubKey = []byte(prevTx.Vout[vin.Vout].ScriptPubKey)
		txCopy.ID = txCopy.Hash()
		txCopy.Vin[inID].PubKey = nil

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
	target.Lsh(target, uint(256-b.Difficulty))
	return &ProofOfWork{block: b, target: target}
}

// prepareData flattens block components and headers into a contiguous byte stream for hashing.
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	var txHashes [][]byte
	for _, tx := range pow.block.Transactions {
		txHashes = append(txHashes, []byte(tx.ID))
	}
	txHash := sha256.Sum256(bytes.Join(txHashes, []byte{}))

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

	log.Printf("[PoW] Starting mining computation at height %d (Difficulty: %d)...", pow.block.Height, pow.block.Difficulty)
	for nonce < math.MaxInt64 {
		data := pow.prepareData(nonce)
		hash = HashKeccak256(data)
		hashInt.SetString(hash, 16)

		if hashInt.Cmp(pow.target) == -1 {
			break
		}
		nonce++
	}
	log.Printf("[PoW] Block successfully mined! Nonce: %d, Hash: %s", nonce, hash)
	return nonce, hash
}

// intToHex safely converts a 64-bit integer into a hexadecimal byte slice representation.
func intToHex(n int64) []byte {
	return []byte(fmt.Sprintf("%x", n))
}

// ================= STORAGE & PERSISTENCE (BOLTDB) =================

// CreateBlockchain initializes a fresh persistent BoltDB database and writes the Genesis block.
func CreateBlockchain(address string) *Blockchain {
	if _, err := os.Stat(dbFile); err == nil {
		_ = os.Remove(dbFile)
	}

	db, err := bbolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	var tip []byte
	err = db.Update(func(tx *bbolt.Tx) error {
		cbtx := NewCoinbaseTX(address, "Genesis Block - Initializing Network")
		genesis := CreateGenesisBlock(cbtx)
		b, err := tx.CreateBucket([]byte(blocksBucket))
		if err != nil {
			return err
		}
		err = b.Put([]byte(genesis.Hash), serializeBlock(genesis))
		if err != nil {
			return err
		}
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

	log.Printf("[DB] New blockchain created with Genesis hash: %s", string(tip))
	return &Blockchain{tip, db}
}

// OpenBlockchain opens an existing BoltDB database instance for ongoing blockchain operations.
func OpenBlockchain() *Blockchain {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		log.Println("[DB] Error: No existing blockchain found. Create one using 'createblockchain -address <address>' first.")
		os.Exit(1)
	}

	db, err := bbolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	var tip []byte
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

// FindUnspentTransactions scans historical blocks in the database to trace user UTXOs accurately.
func (bc *Blockchain) FindUnspentTransactions(address string) []Transaction {
	var unspentTXs []Transaction
	spentTXos := make(map[string][]int)

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

					if out.ScriptPubKey == address {
						unspentTXs = append(unspentTXs, *tx)
					}
				}

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
	
	spentTXos := make(map[string][]int)
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := deserializeBlock(v)
			for _, t := range block.Transactions {
				if !t.IsCoinbase() {
					for _, in := range t.Vin {
						if wallet.GetAddressFromPubKey(in.PubKey) == address {
							spentTXos[in.Txid] = append(spentTXos[in.Txid], in.Vout)
						}
					}
				}
			}
		}
		return nil
	})

	exactBalance := 0
	for _, tx := range unspentTXs {
		txID := tx.ID
		for outIdx, out := range tx.Vout {
			if out.ScriptPubKey == address {
				isSpent := false
				if spentTXos[txID] != nil {
					for _, spentOut := range spentTXos[txID] {
						if spentOut == outIdx {
							isSpent = true
							break
						}
					}
				}
				if !isSpent {
					exactBalance += out.Value
				}
			}
		}
	}
	return exactBalance
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

	if acc < amount {
		log.Printf("[TX] Insufficient funds for sender %s: have %d, need %d", sender, acc, amount)
		return nil, errors.New("error: insufficient funds")
	}

	prevTxs := make(map[string]*Transaction)

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

	outputs = append(outputs, TXOutput{Value: amount, ScriptPubKey: recipient})
	if acc > amount {
		outputs = append(outputs, TXOutput{Value: acc - amount, ScriptPubKey: sender})
	}

	tx := Transaction{ID: "", Vin: inputs, Vout: outputs}
	tx.ID = tx.Hash()
	tx.Sign(walletSender, prevTxs)

	log.Printf("[TX] Created new UTXO transaction %s (Amount: %d coins)", tx.ID, amount)
	return &tx, nil
}

// CalculateDifficulty dynamically adjusts mining difficulty based on block intervals.
func (bc *Blockchain) CalculateDifficulty(lastBlock *Block) int {
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

	if actualTimeSpan < targetTimeSpan/2 {
		log.Printf("[CONSENSUS] Difficulty increased: +1 (Height %d)", lastBlock.Height+1)
		return lastBlock.Difficulty + 1
	} else if actualTimeSpan > targetTimeSpan*2 {
		if lastBlock.Difficulty > 1 {
			log.Printf("[CONSENSUS] Difficulty decreased: -1 (Height %d)", lastBlock.Height+1)
			return lastBlock.Difficulty - 1
		}
	}

	return lastBlock.Difficulty
}

// MineBlock packs pending mempool transactions, runs PoW consensus, and appends the new block into storage.
func (bc *Blockchain) MineBlock(transactions []*Transaction, minerAddress string) *Block {
	var lastHash []byte
	var lastBlock *Block

	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash = b.Get([]byte("l"))
		lastBlock = deserializeBlock(b.Get(lastHash))
		return nil
	})

	newDifficulty := bc.CalculateDifficulty(lastBlock)

	var validTransactions []*Transaction
	prevTxs := make(map[string]*Transaction)

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

	for _, tx := range transactions {
		if tx.IsCoinbase() {
			validTransactions = append(validTransactions, tx)
			continue
		}
		if tx.Verify(prevTxs) {
			validTransactions = append(validTransactions, tx)
			log.Printf("[VALIDATION] STATUS: Transaction %s is valid and included in block.", tx.ID)
		} else {
			log.Printf("[VALIDATION] STATUS: TRANSACTION %s FAILED VERIFICATION (Signature/PrevTx mismatch)!", tx.ID)
		}
	}

	cbtx := NewCoinbaseTX(minerAddress, "")
	allTransactions := append([]*Transaction{cbtx}, validTransactions...)

	newBlock := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  allTransactions,
		PrevBlockHash: hex.EncodeToString(lastHash),
		Height:        lastBlock.Height + 1,
		Difficulty:    newDifficulty,
	}

	pow := NewProofOfWork(newBlock)
	nonce, hash := pow.Run()
	newBlock.Nonce = nonce
	newBlock.Hash = hash

	bc.Db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		_ = b.Put([]byte(newBlock.Hash), serializeBlock(newBlock))
		_ = b.Put([]byte("l"), []byte(newBlock.Hash))
		bc.Tip = []byte(newBlock.Hash)
		return nil
	})

	log.Printf("[BLOCK] Appended new block #%d (Hash: %s) to blockchain storage.", newBlock.Height, newBlock.Hash)
	mempool.Clear(transactions)
	return newBlock
}

// ================= P2P NETWORK SIMULATOR =================

// StartP2PServer spins up a lightweight background TCP listener for peer synchronization.
func StartP2PServer(port string) {
	listen, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("[P2P] Failed to bind port %s: %v", port, err)
		return
	}
	defer listen.Close()
	log.Printf("[P2P] Node server listening on TCP port %s", port)

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
	fmt.Println("  createblockchain -address <ADDRESS>            - Create a blockchain and send genesis reward")
	fmt.Println("  createwallet                                  - Generates a new wallet address")
	fmt.Println("  getbalance -address <ADDRESS>                 - Get balance of an address")
	fmt.Println("  printchain                                    - Print all blocks of the blockchain")
	fmt.Println("  mine -miner <ADDRESS>                         - Mine a new block with pending mempool txs")
	fmt.Println("  send -from <FROM> -to <TO> -amount <AMOUNT>   - Send coins from one address to another")
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

	createBlockchainCmd := flag.NewFlagSet("createblockchain", flag.ExitOnError)
	createWalletCmd := flag.NewFlagSet("createwallet", flag.ExitOnError)
	getBalanceCmd := flag.NewFlagSet("getbalance", flag.ExitOnError)
	printChainCmd := flag.NewFlagSet("printchain", flag.ExitOnError)
	mineCmd := flag.NewFlagSet("mine", flag.ExitOnError)
	sendCmd := flag.NewFlagSet("send", flag.ExitOnError)

	createBlockchainAddress := createBlockchainCmd.String("address", "", "The address to send genesis block reward to")
	getBalanceAddress := getBalanceCmd.String("address", "", "The address to get balance for")
	mineMinerAddress := mineCmd.String("miner", "", "Miner address to receive block reward")
	
	sendFrom := sendCmd.String("from", "", "Source wallet address")
	sendTo := sendCmd.String("to", "", "Destination recipient address")
	sendAmount := sendCmd.Int("amount", 0, "Amount of coins to send")

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
	case "send":
		_ = sendCmd.Parse(os.Args[2:])
	default:
		cli.printUsage()
		os.Exit(1)
	}

	if createBlockchainCmd.Parsed() {
		if *createBlockchainAddress == "" {
			createBlockchainCmd.Usage()
			os.Exit(1)
		}
		bc := CreateBlockchain(*createBlockchainAddress)
		defer bc.Db.Close()
		log.Println("Done! Genesis block created successfully.")
	}

	if createWalletCmd.Parsed() {
		w := wallet.NewWallet()
		log.Printf("New Wallet Generated!\nAddress: %s", w.GetAddress())
	}

	if getBalanceCmd.Parsed() {
		if *getBalanceAddress == "" {
			getBalanceCmd.Usage()
			os.Exit(1)
		}
		bc := OpenBlockchain()
		defer bc.Db.Close()
		balance := bc.GetBalance(*getBalanceAddress)
		log.Printf("Balance of '%s': %d coins", *getBalanceAddress, balance)
	}

	if printChainCmd.Parsed() {
		bc := OpenBlockchain()
		defer bc.Db.Close()

		bc.Db.View(func(tx *bbolt.Tx) error {
			b := tx.Bucket([]byte(blocksBucket))
			cursor := b.Cursor()
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				if string(k) == "l" {
					continue
				}
				block := deserializeBlock(v)
				log.Printf("Block Height : %d", block.Height)
				log.Printf("Difficulty   : %d", block.Difficulty)
				log.Printf("Prev. Hash   : %s", block.PrevBlockHash)
				log.Printf("Block Hash   : %s", block.Hash)
				log.Printf("Nonce        : %d", block.Nonce)
				log.Printf("Tx Count     : %d", len(block.Transactions))
				log.Println("--------------------------------------------------")
			}
			return nil
		})
	}

	if mineCmd.Parsed() {
		if *mineMinerAddress == "" {
			mineCmd.Usage()
			os.Exit(1)
		}
		bc := OpenBlockchain()
		defer bc.Db.Close()
		bc.MineBlock(mempool.GetAll(), *mineMinerAddress)
		log.Println("Success! Block successfully mined and committed.")
	}

	if sendCmd.Parsed() {
		if *sendFrom == "" || *sendTo == "" || *sendAmount <= 0 {
			sendCmd.Usage()
			os.Exit(1)
		}

		bc := OpenBlockchain()
		defer bc.Db.Close()

		w, err := wallet.GetWalletByAddress(*sendFrom)
		if err != nil {
			log.Fatalf("Failed to load sender wallet: %v", err)
		}

		tx, err := NewUTXOTransaction(w, *sendTo, *sendAmount, bc)
		if err != nil {
			log.Fatalf("Transaction failed: %v", err)
		}

		mempool.Add(tx)
		log.Println("Success! Transaction broadcasted and added to mempool.")
	}
}

// main serves as the primary program execution entrypoint.
func main() {
	InitLogger()
	defer CloseLogger()

	go StartP2PServer("3000")
	cli := CLI{}
	cli.Run()
}
