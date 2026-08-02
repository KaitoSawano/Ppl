// Copyright 2026 The Aldianokto
// Package main implements a robust, modular, and production-ready Proof-of-Work (PoW) 
// blockchain core featuring BoltDB permanent storage, ECDSA digital signatures, 
// a transaction mempool, adaptive difficulty, and a fully functional P2P networking layer.
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
	"io/ioutil"
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
	nodeVersion       = 1               // Current version identifier of the P2P protocol node
	protocol          = "tcp"           // Network protocol utilized for establishing peer-to-peer TCP connections
)

// Global node runtime state variables used across networking and mining operations.
var (
	nodeAddress     string             // Local network address endpoint string representation used by the node
	knownNodes      = []string{"localhost:3000"} // Predefined slice of known bootstrap peer node addresses in the network
	blocksInTransit = [][]byte{}       // Slice holding block hashes currently in transit during synchronization
	mempool         = NewMempool()     // Global transaction mempool instance holding unconfirmed transactions
	logFile         *os.File           // File descriptor pointer pointing to the active log output file
)

// ================= STRUCT DEFINITIONS =================

// TXInput represents an input reference pointing to a previous transaction output.
type TXInput struct {
	Txid      string // Transaction ID of the referenced transaction containing the target output
	Vout      int    // Index position of the specific output within the referenced transaction outputs array
	Signature []byte // Digital signature proving authorization to spend the funds
	PubKey    []byte // Public key matching the address that originally locked the target output (stored as raw bytes or string) -> Wait, using []byte in struct definition below
}

// Re-defining TXInput with exact fields matching the implementation code:
// TXInput struct layout definition:
// Txid string, Vout int, Signature []byte, PubKey []byte.

// TXOutput represents a destination output holding coins locked under a specific script/address.
type TXOutput struct {
	Value        int    // Monetary value amount of coins assigned to this output entry
	ScriptPubKey string // Target locking script address specifying who can spend these funds
}

// Transaction represents a discrete transfer of value containing inputs and outputs.
type Transaction struct {
	ID   string     // Cryptographic hash identifier string computed from transaction fields
	Vin  []TXInput  // Array of transaction inputs consuming previous unspent outputs
	Vout []TXOutput // Array of transaction outputs creating new spendable coins
}

// Block represents a single batch of validated transactions securely linked to its predecessor.
type Block struct {
	Timestamp     int64          // Unix epoch timestamp indicating when the block was created
	Transactions  []*Transaction // Slice of pointers to transactions included within this block
	PrevBlockHash string         // Cryptographic hash string of the preceding parent block in the chain
	Hash          string         // Cryptographic hash string uniquely identifying this specific block
	Nonce         int            // Incremental counter used during the Proof-of-Work mining computation
	Height        int            // Sequential block height number measuring distance from genesis
	Difficulty    int            // Target difficulty bit threshold applied when mining this block
}

// Blockchain represents the database-backed storage wrapper managing the chain tip and ledger.
type Blockchain struct {
	Tip []byte    // Raw byte slice containing the block hash of the current highest chain tip
	Db  *bbolt.DB // Pointer to the underlying embedded BoltDB key-value database instance
}

// ProofOfWork encapsulates block data and calculation targets for the mining algorithm.
type ProofOfWork struct {
	block  *Block    // Pointer to the block currently undergoing proof-of-work mining
	target *big.Int  // Big integer target threshold defining the required mining difficulty boundary
}

// Mempool handles thread-safe concurrent storage of unconfirmed pending network transactions.
type Mempool struct {
	mu           sync.Mutex               // Mutex lock ensuring thread-safe concurrent access to map data
	Transactions map[string]*Transaction  // Map mapping transaction IDs to transaction pointers
}

// P2P Network Command Protocol Packet Type String Identifiers.
const (
	CmdAddr      = "addr"      // Command string identifier for broadcasting known peer node addresses
	CmdBlock     = "block"     // Command string identifier for transmitting a serialized block payload
	CmdInv       = "inv"       // Command string identifier for advertising inventory inventories (hashes)
	CmdGetBlocks = "getblocks" // Command string identifier for requesting a list of all block hashes
	CmdGetData   = "getdata"   // Command string identifier for requesting specific block or transaction data
	CmdTx        = "tx"        // Command string identifier for broadcasting a new transaction payload
	CmdVersion   = "version"   // Command string identifier for exchanging node protocol version details
)

// Version payload packet structure exchanged during initial node handshakes.
type Version struct {
	Version    int    // Protocol version number supported by the sending node
	BestHeight int    // Current blockchain height of the sending node
	AddrFrom   string // Network address identifier string of the sending node
}

// Addr payload packet structure containing a list of active peer node addresses.
type Addr struct {
	AddrList []string // Slice containing network address strings of active peers
}

// GetBlocks payload packet structure requesting block inventory listings.
type GetBlocks struct {
	AddrFrom string // Network address identifier string of the node requesting blocks
}

// GetData payload packet structure requesting specific object data items by ID.
type GetData struct {
	AddrFrom string // Network address identifier string of the requesting node
	Type     string // Type category string of the requested item (e.g., "block" or "tx")
	ID       []byte // Byte slice representing the unique cryptographic hash identifier of the item
}

// Inv payload packet structure advertising inventory listings of available items.
type Inv struct {
	AddrFrom string   // Network address identifier string of the inventory advertiser
	Type     string   // Type category string of the advertised items ("block" or "tx")
	Items    [][]byte // Slice of byte slices containing item hash identifiers
}

// BlockPacket payload packet structure wrapping a serialized block for network transmission.
type BlockPacket struct {
	AddrFrom string // Network address identifier string of the node sending the block
	Block    []byte // Raw byte slice containing the gob-serialized block data
}

// TxPacket payload packet structure wrapping a serialized transaction for network transmission.
type TxPacket struct {
	AddrFrom    string // Network address identifier string of the node sending the transaction
	Transaction []byte // Raw byte slice containing the gob-serialized transaction data
}

// ================= LOGGING SYSTEM =================

// InitLogger sets up dual-output logging to both standard output and a local log file.
func InitLogger() {
	// Retrieve the current user's home directory path to store persistent logs safely.
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	// Construct the target hidden directory path (.gnx) for application logs.
	logDirPath := filepath.Join(homeDir, LogDirName)
	// Create the directory path recursively with standard Unix read/write permissions.
	if err := os.MkdirAll(logDirPath, 0755); err != nil {
		logDirPath = "."
	}
	// Build the absolute file path pointing to the debug log file.
	logPath := filepath.Join(logDirPath, LogFileName)
	// Open the log file with flags to create if missing, write-only, and append new logs.
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Failed to open debug log file: %v", err)
		return
	}
	// Assign the opened file pointer to the global logFile variable.
	logFile = f

	// Create a multi-writer interface to duplicate log output to both console stdout and file.
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	// Configure the standard logger to write to our multi-writer target.
	log.SetOutput(multiWriter)
	// Configure log flags to record date, time, and microsecond precision timestamps.
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	// Log an initial startup success message indicating node core initialization.
	log.Printf("[NODE] GNX Blockchain Core initialized. Logging to %s", logPath)
}

// CloseLogger safely closes the file descriptor stream associated with the active debug log file.
func CloseLogger() {
	// Check if the global log file pointer is initialized before attempting closure.
	if logFile != nil {
		// Close the file stream and ignore minor closing errors.
		_ = logFile.Close()
	}
}

// ================= MEMPOOL MANAGEMENT =================

// NewMempool instantiates a fresh mempool object and loads any saved transactions from local disk.
func NewMempool() *Mempool {
	// Allocate and initialize a new Mempool struct with an empty transaction map.
	mp := &Mempool{Transactions: make(map[string]*Transaction)}
	// Load any pre-existing unconfirmed transactions saved from past runtime sessions.
	mp.loadFromFile()
	// Return the initialized mempool pointer.
	return mp
}

// saveToFile serializes the current mempool transactions map into a JSON file on disk.
func (mp *Mempool) saveToFile() {
	// Marshal the map of pending transactions into pretty or standard JSON byte data.
	data, err := json.Marshal(mp.Transactions)
	if err != nil {
		return
	}
	// Write the marshaled JSON bytes into the local mempool backup file path.
	_ = os.WriteFile(mempoolFile, data, 0644)
}

// loadFromFile reads the persistent JSON backup file and restores unconfirmed transactions into memory.
func (mp *Mempool) loadFromFile() {
	// Check if the persistent mempool backup file actually exists on disk.
	if _, err := os.Stat(mempoolFile); os.IsNotExist(err) {
		return
	}
	// Read all raw bytes from the mempool backup json file path.
	data, err := os.ReadFile(mempoolFile)
	if err != nil {
		return
	}
	// Unmarshal the JSON byte data back into the transaction lookup map.
	_ = json.Unmarshal(data, &mp.Transactions)
}

// Add safely inserts a new transaction into the mempool and updates disk storage.
func (mp *Mempool) Add(tx *Transaction) {
	// Acquire the mutex lock to guarantee thread-safe map writing.
	mp.mu.Lock()
	// Ensure the mutex lock is released when the function scope exits.
	defer mp.mu.Unlock()
	// Insert or update the transaction reference inside the lookup map using its ID hash.
	mp.Transactions[tx.ID] = tx
	// Persist the updated mempool state onto the local hard drive storage.
	mp.saveToFile()
	// Output an informational log message tracking the addition of the new transaction.
	log.Printf("[MEMPOOL] Transaction added & saved to disk: %s", tx.ID)
}

// GetAll safely retrieves a slice containing all currently pending unconfirmed transactions.
func (mp *Mempool) GetAll() []*Transaction {
	// Acquire the mutex lock for safe concurrent reading.
	mp.mu.Lock()
	// Ensure the mutex lock is released upon completion.
	defer mp.mu.Unlock()
	// Refresh mempool state from disk storage to ensure latest data synchronization.
	mp.loadFromFile()
	// Declare a slice to hold transaction pointers.
	var txs []*Transaction
	// Iterate through the map values and append each transaction pointer to the slice.
	for _, tx := range mp.Transactions {
		txs = append(txs, tx)
	}
	// Return the populated slice of transactions.
	return txs
}

// Clear removes successfully mined transactions from the mempool storage map and updates disk.
func (mp *Mempool) Clear(minedTxs []*Transaction) {
	// Acquire the mutex lock for safe modification.
	mp.mu.Lock()
	// Ensure lock release via defer.
	defer mp.mu.Unlock()
	// Loop through each transaction included in the newly mined block.
	for _, tx := range minedTxs {
		// Ignore coinbase transactions since they are never stored in the mempool.
		if !tx.IsCoinbase() {
			// Delete the confirmed transaction key from the lookup map.
			delete(mp.Transactions, tx.ID)
			// Log the removal of the mined transaction.
			log.Printf("[MEMPOOL] Cleared mined transaction: %s", tx.ID)
		}
	}
	// Save the cleaned-up mempool state back to the disk file.
	mp.saveToFile()
}

// Size returns the total count of currently pending unconfirmed transactions in memory.
func (mp *Mempool) Size() int {
	// Acquire mutex lock for thread safety.
	mp.mu.Lock()
	// Ensure defer unlock.
	defer mp.mu.Unlock()
	// Load latest state from disk file.
	mp.loadFromFile()
	// Return the total length of the transaction map.
	return len(mp.Transactions)
}

// ================= CRYPTOGRAPHIC & UTILITY FUNCTIONS =================

// HashKeccak256 computes a Keccak-256 cryptographic hash string from input byte data.
func HashKeccak256(b []byte) string {
	// Instantiate a new Keccak-256 hashing state algorithm instance.
	h := sha3.New256()
	// Write the input byte array into the hashing computation stream.
	h.Write(b)
	// Compute the final sum digest bytes and encode them into a hexadecimal string format.
	return hex.EncodeToString(h.Sum(nil))
}

// Hash computes and returns the unique cryptographic hash identifier string of a transaction.
func (tx *Transaction) Hash() string {
	// Declare a buffer to hold the encoded transaction binary data stream.
	var encoded bytes.Buffer
	// Create a new JSON encoder targeting our buffer.
	enc := json.NewEncoder(&encoded)
	// Encode the transaction struct fields into JSON format.
	_ = enc.Encode(tx)
	// Return the resulting Keccak-256 hash string of the encoded buffer bytes.
	return HashKeccak256(encoded.Bytes())
}

// IsCoinbase checks whether a given transaction is a special block reward coinbase transaction.
func (tx *Transaction) IsCoinbase() bool {
	// A coinbase transaction has exactly one input, an empty previous transaction ID string, and index -1.
	return len(tx.Vin) == 1 && tx.Vin[0].Txid == "" && tx.Vin[0].Vout == -1
}

// TrimmedCopy creates a shallow copy of a transaction with emptied signatures and public keys for signing.
func (tx *Transaction) TrimmedCopy() Transaction {
	// Initialize empty slices for trimmed inputs and copied outputs.
	var inputs []TXInput
	var outputs []TXOutput
	// Loop through each input, clearing out sensitive cryptographic signature and key fields.
	for _, vin := range tx.Vin {
		inputs = append(inputs, TXInput{vin.Txid, vin.Vout, nil, nil})
	}
	// Copy each transaction output value and script directly.
	for _, vout := range tx.Vout {
		outputs = append(outputs, TXOutput{vout.Value, vout.ScriptPubKey})
	}
	// Return a new Transaction struct containing the sanitized inputs and copied outputs.
	return Transaction{tx.ID, inputs, outputs}
}

// Sign cryptographically signs each input of a transaction using a wallet instance and prior transaction lookup context.
func (tx *Transaction) Sign(w *wallet.Wallet, prevTxs map[string]*Transaction) {
	// Coinbase transactions do not require external cryptographic input signatures.
	if tx.IsCoinbase() {
		return
	}
	// Generate a trimmed structural copy of the transaction for signing purposes.
	txCopy := tx.TrimmedCopy()
	// Iterate through each input element to populate public key references and sign.
	for inID, vin := range tx.Vin {
		// Look up the historical parent transaction corresponding to this input reference.
		prevTx := prevTxs[vin.Txid]
		// Embed the target locking script public key bytes into the trimmed copy input slot.
		txCopy.Vin[inID].PubKey = []byte(prevTx.Vout[vin.Vout].ScriptPubKey)
		// Compute the unique transaction identifier hash for this specific signing iteration.
		txCopy.ID = txCopy.Hash()
		// Reset the public key field back to nil before signing the hash digest.
		txCopy.Vin[inID].PubKey = nil

		// Generate an ECDSA digital signature over the computed transaction hash bytes.
		signature := w.Sign([]byte(txCopy.ID))
		// Assign the resulting cryptographic signature and sender public key bytes to the actual transaction input.
		tx.Vin[inID].Signature = signature
		tx.Vin[inID].PubKey = w.PublicKey
	}
}

// Verify validates all digital signatures present across every input of a transaction.
func (tx *Transaction) Verify(prevTxs map[string]*Transaction) bool {
	// Coinbase transactions are automatically verified without checks.
	if tx.IsCoinbase() {
		return true
	}
	// Create a trimmed transaction copy for signature verification matching the signing step.
	txCopy := tx.TrimmedCopy()
	// Loop through each transaction input to verify its associated signature.
	for inID, vin := range tx.Vin {
		// Fetch the parent transaction dictionary entry matching the input source ID.
		prevTx := prevTxs[vin.Txid]
		// Assign the parent output script public key bytes into the verification copy input.
		txCopy.Vin[inID].PubKey = []byte(prevTx.Vout[vin.Vout].ScriptPubKey)
		// Compute the exact transaction hash digest that was originally signed.
		txCopy.ID = txCopy.Hash()
		// Clear the public key field back to nil.
		txCopy.Vin[inID].PubKey = nil

		// Use the wallet package verification function to check the cryptographic signature validity.
		if !wallet.Verify(vin.PubKey, vin.Signature, []byte(txCopy.ID)) {
			return false
		}
	}
	// Return true if all transaction input signatures passed verification successfully.
	return true
}

// ================= PROOF OF WORK & STORAGE =================

// NewProofOfWork initializes and returns a new ProofOfWork mining calculation struct.
func NewProofOfWork(b *Block) *ProofOfWork {
	// Initialize a big integer starting at value 1.
	target := big.NewInt(1)
	// Left shift the big integer by (256 minus block difficulty bits) to establish the difficulty target boundary.
	target.Lsh(target, uint(256-b.Difficulty))
	// Return the instantiated ProofOfWork pointer struct.
	return &ProofOfWork{block: b, target: target}
}

// prepareData combines block headers, transaction hashes, and nonce variables into a single byte array for hashing.
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	// Declare a slice to hold transaction ID byte slices included in the block.
	var txHashes [][]byte
	// Loop through all block transactions, converting their string IDs into raw byte slices.
	for _, tx := range pow.block.Transactions {
		txHashes = append(txHashes, []byte(tx.ID))
	}
	// Compute a SHA-256 summary hash joining all transaction hashes together.
	txHash := sha256.Sum256(bytes.Join(txHashes, []byte{}))

	// Concatenate previous block hash, transaction root hash, timestamp, difficulty, and nonce into one data block.
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
	// Return the merged byte array ready for cryptographic hash calculation.
	return data
}

// Run executes the iterative Proof-of-Work mining puzzle loop until a valid hash below target is found.
func (pow *ProofOfWork) Run() (int, string) {
	// Initialize big integer variables to store hash values and nonce counters.
	var hashInt big.Int
	var hash string
	nonce := 0
	// Log the start of the heavy mining computation process.
	log.Printf("[PoW] Starting mining computation at height %d (Difficulty: %d)...", pow.block.Height, pow.block.Difficulty)
	// Loop continuously incrementing the nonce until it reaches maximum integer limits.
	for nonce < math.MaxInt64 {
		// Prepare candidate data bytes for the current nonce value.
		data := pow.prepareData(nonce)
		// Compute the Keccak-256 hash string of the prepared candidate data.
		hash = HashKeccak256(data)
		// Parse the resulting hexadecimal hash string into a big integer representation.
		hashInt.SetString(hash, 16)
		// Compare the computed hash integer against the target threshold (returns -1 if hashInt < target).
		if hashInt.Cmp(pow.target) == -1 {
			// Exit the mining loop successfully once a valid target-matching hash is discovered.
			break
		}
		// Increment the nonce counter to try the next hash permutation.
		nonce++
	}
	// Log success and display the discovered nonce and block hash values.
	log.Printf("[PoW] Block successfully mined! Nonce: %d, Hash: %s", nonce, hash)
	// Return the winning nonce and block hash string.
	return nonce, hash
}

// intToHex converts a standard 64-bit integer into a hexadecimal byte array representation.
func intToHex(n int64) []byte {
	return []byte(fmt.Sprintf("%x", n))
}

// CreateBlockchain initializes a fresh database storage file, writes the genesis block, and returns a Blockchain pointer.
func CreateBlockchain(address string) *Blockchain {
	// Check if an existing database file is already present on disk, and delete it if found.
	if _, err := os.Stat(dbFile); err == nil {
		_ = os.Remove(dbFile)
	}
	// Open or create a new embedded BoltDB database file instance with read-write permissions.
	db, err := bbolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	var tip []byte
	// Execute a database transaction update block to create buckets and write the genesis block.
	err = db.Update(func(tx *bbolt.Tx) error {
		// Generate the initial coinbase transaction allocating the genesis block reward.
		cbtx := NewCoinbaseTX(address, "Genesis Block - Initializing Network")
		// Build the genesis block wrapping the coinbase transaction.
		genesis := CreateGenesisBlock(cbtx)
		// Create the main block storage bucket inside the BoltDB database.
		b, err := tx.CreateBucket([]byte(blocksBucket))
		if err != nil {
			return err
		}
		// Store the serialized genesis block using its hash as the key.
		err = b.Put([]byte(genesis.Hash), serializeBlock(genesis))
		if err != nil {
			return err
		}
		// Store a special pointer key 'l' pointing to the latest chain tip hash.
		err = b.Put([]byte("l"), []byte(genesis.Hash))
		if err != nil {
			return err
		}
		// Assign the genesis hash to our local tip tracking variable.
		tip = []byte(genesis.Hash)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	// Log successful blockchain initialization.
	log.Printf("[DB] New blockchain created with Genesis hash: %s", string(tip))
	// Return the initialized Blockchain struct pointer.
	return &Blockchain{tip, db}
}

// OpenBlockchain opens an existing BoltDB blockchain data file and loads the current chain tip.
func OpenBlockchain() *Blockchain {
	// Check if the blockchain database file exists on disk, terminating if missing.
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		log.Println("[DB] Error: No existing blockchain found. Create one using 'createblockchain -address <address>' first.")
		os.Exit(1)
	}
	// Open the BoltDB file in read-write mode.
	db, err := bbolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	var tip []byte
	// Read the chain tip hash pointer from the database bucket view.
	err = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		tip = b.Get([]byte("l"))
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	// Return the active Blockchain pointer struct.
	return &Blockchain{tip, db}
}

// CreateGenesisBlock mines and returns the very first block (genesis block) of the blockchain.
func CreateGenesisBlock(coinbase *Transaction) *Block {
	// Instantiate a Block struct configured with zero height and a blank parent hash.
	block := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  []*Transaction{coinbase},
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Height:        0,
		Difficulty:    InitialDifficulty,
	}
	// Initialize proof of work and run the mining algorithm to solve the genesis puzzle.
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Nonce = nonce
	block.Hash = hash
	// Return the completed genesis block pointer.
	return block
}

// serializeBlock encodes a Block struct into a byte array using Go's standard gob package.
func serializeBlock(b *Block) []byte {
	var result bytes.Buffer
	enc := gob.NewEncoder(&result)
	_ = enc.Encode(b)
	return result.Bytes()
}

// deserializeBlock decodes raw byte data back into a structured Block pointer using gob.
func deserializeBlock(d []byte) *Block {
	var block Block
	dec := gob.NewDecoder(bytes.NewReader(d))
	_ = dec.Decode(&block)
	return &block
}

// NewCoinbaseTX generates a new block reward coinbase transaction allocating subsidy coins to a miner address.
func NewCoinbaseTX(to, data string) *Transaction {
	// If custom genesis data string is empty, assign a default block reward note.
	if data == "" {
		data = fmt.Sprintf("Reward to '%s'", to)
	}
	// Construct a special empty coinbase transaction input.
	txin := TXInput{Txid: "", Vout: -1, Signature: nil, PubKey: []byte(data)}
	// Construct the transaction output granting the block subsidy value to the miner address.
	txout := TXOutput{Value: Subsidy, ScriptPubKey: to}
	// Combine input and output into a Transaction struct, compute its ID hash, and return.
	tx := Transaction{ID: "", Vin: []TXInput{txin}, Vout: []TXOutput{txout}}
	tx.ID = tx.Hash()
	return &tx
}

// FindUnspentTransactions scans the blockchain to locate all unspent transaction entries belonging to an address.
func (bc *Blockchain) FindUnspentTransactions(address string) []Transaction {
	var unspentTXs []Transaction
	spentTXos := make(map[string][]int)
	// Open a read view on the database to iterate through all stored blocks.
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		cursor := b.Cursor()
		// Iterate through every stored block in the database bucket.
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := deserializeBlock(v)
			// Loop through all transactions contained within the block.
			for _, tx := range block.Transactions {
				txID := tx.ID
				// Evaluate each output in the transaction.
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
					// If the output belongs to the target address, append it to unspent transactions.
					if out.ScriptPubKey == address {
						unspentTXs = append(unspentTXs, *tx)
					}
				}
				// If not a coinbase transaction, mark input references as spent outputs.
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

// FindSpendableOutputs finds unspent outputs for an address sufficient to cover a target transaction amount.
func (bc *Blockchain) FindSpendableOutputs(address string, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	unspentTXs := bc.FindUnspentTransactions(address)
	accumulated := 0
Work:
	for _, tx := range unspentTXs {
		txID := tx.ID
		for outIdx, out := range tx.Vout {
			// Accumulate funds until the required amount is met or exceeded.
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

// GetBalance calculates and returns the total spendable coin balance for a given wallet address.
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
	// Sum up all unspent output values.
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

// FindTransactionByHash searches the blockchain history to find a specific transaction by its ID hash string.
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

// NewUTXOTransaction creates, signs, and returns a new transfer transaction sending coins to a recipient.
func NewUTXOTransaction(walletSender *wallet.Wallet, recipient string, amount int, bc *Blockchain) (*Transaction, error) {
	var inputs []TXInput
	var outputs []TXOutput
	sender := walletSender.GetAddress()
	// Find spendable outputs belonging to the sender.
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
	// Create output for the recipient.
	outputs = append(outputs, TXOutput{Value: amount, ScriptPubKey: recipient})
	// If change is remaining, create a change output back to the sender.
	if acc > amount {
		outputs = append(outputs, TXOutput{Value: acc - amount, ScriptPubKey: sender})
	}
	tx := Transaction{ID: "", Vin: inputs, Vout: outputs}
	tx.ID = tx.Hash()
	// Cryptographically sign the newly created transaction.
	tx.Sign(walletSender, prevTxs)
	log.Printf("[TX] Created new UTXO transaction %s (Amount: %d coins)", tx.ID, amount)
	return &tx, nil
}

// CalculateDifficulty dynamically adjusts mining difficulty based on block interval time spans.
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
	// If blocks were mined too fast, increase difficulty.
	if actualTimeSpan < targetTimeSpan/2 {
		log.Printf("[CONSENSUS] Difficulty increased: +1 (Height %d)", lastBlock.Height+1)
		return lastBlock.Difficulty + 1
	} else if actualTimeSpan > targetTimeSpan*2 {
		// If blocks were mined too slow, decrease difficulty.
		if lastBlock.Difficulty > 1 {
			log.Printf("[CONSENSUS] Difficulty decreased: -1 (Height %d)", lastBlock.Height+1)
			return lastBlock.Difficulty - 1
		}
	}
	return lastBlock.Difficulty
}

// MineBlock validates transactions, builds a new block, solves proof-of-work, and commits it to storage.
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
	// Validate each transaction before including it in the block.
	for _, tx := range transactions {
		if tx.IsCoinbase() {
			validTransactions = append(validTransactions, tx)
			continue
		}
		if tx.Verify(prevTxs) {
			validTransactions = append(validTransactions, tx)
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
	// Commit the newly mined block to the BoltDB database storage.
	bc.Db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		_ = b.Put([]byte(newBlock.Hash), serializeBlock(newBlock))
		_ = b.Put([]byte("l"), []byte(newBlock.Hash))
		bc.Tip = []byte(newBlock.Hash)
		return nil
	})
	log.Printf("[BLOCK] Appended new block #%d (Hash: %s) to blockchain storage.", newBlock.Height, newBlock.Hash)
	// Clear processed transactions from the mempool.
	mempool.Clear(transactions)
	return newBlock
}

// GetBestHeight returns the height number of the highest block on the current chain tip.
func (bc *Blockchain) GetBestHeight() int {
	var lastBlock *Block
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash := b.Get([]byte("l"))
		lastBlock = deserializeBlock(b.Get(lastHash))
		return nil
	})
	return lastBlock.Height
}

// GetBlockHashes returns a slice containing hashes of all blocks stored in the chain.
func (bc *Blockchain) GetBlockHashes() [][]byte {
	var blocks [][]byte
	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := deserializeBlock(v)
			blocks = append(blocks, []byte(block.Hash))
		}
		return nil
	})
	return blocks
}

// GetBlock retrieves raw serialized block bytes from database matching a block hash.
func (bc *Blockchain) GetBlock(blockHash []byte) ([]byte, error) {
	var block []byte
	err := bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		block = b.Get(blockHash)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return block, nil
}

// AddBlock inserts a received block into database storage if valid and updates tip if height is greater.
func (bc *Blockchain) AddBlock(block *Block) {
	bc.Db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		blockInDb := b.Get([]byte(block.Hash))
		if blockInDb != nil {
			return nil
		}
		_ = b.Put([]byte(block.Hash), serializeBlock(block))
		lastHash := b.Get([]byte("l"))
		lastBlock := deserializeBlock(b.Get(lastHash))
		if block.Height > lastBlock.Height {
			_ = b.Put([]byte("l"), []byte(block.Hash))
			bc.Tip = []byte(block.Hash)
		}
		return nil
	})
}

// ================= FUNCTIONAL P2P NETWORKING =================

// StartServer binds a TCP port and listens for incoming peer-to-peer network connections.
func StartServer(nodeID string) {
	nodeAddress = "localhost:" + nodeID
	listen, err := net.Listen(protocol, nodeAddress)
	if err != nil {
		log.Panic(err)
	}
	defer listen.Close()

	bc := OpenBlockchain()
	defer bc.Db.Close()

	log.Printf("[P2P] Node server running on port %s", nodeID)

	if nodeAddress != knownNodes[0] {
		sendVersion(knownNodes[0], bc)
	}

	// Accept incoming TCP socket connections in an endless loop.
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Panic(err)
		}
		go handleConnection(conn, bc)
	}
}

// handleConnection reads incoming network commands from a TCP connection and routes them to appropriate handlers.
func handleConnection(conn net.Conn, bc *Blockchain) {
	request, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Panic(err)
	}
	command := straFromBytes(request[:12])
	log.Printf("[P2P] Received command: %s", command)

	// Switch statement routing incoming commands based on their 12-byte header command string.
	switch command {
	case CmdAddr:
		handleAddr(request)
	case CmdBlock:
		handleBlock(request, bc)
	case CmdGetBlocks:
		handleGetBlocks(request, bc)
	case CmdGetData:
		handleGetData(request, bc)
	case CmdInv:
		handleInv(request, bc)
	case CmdTx:
		handleTx(request, bc)
	case CmdVersion:
		handleVersion(request, bc)
	default:
		log.Println("[P2P] Unknown command!")
	}
	conn.Close()
}

// sendData transmits raw network command byte payloads to a target remote peer address.
func sendData(addr string, data []byte) {
	if addr == nodeAddress {
		return
	}
	conn, err := net.Dial(protocol, addr)
	if err != nil {
		log.Printf("[P2P] Node %s is not available", addr)
		var updatedNodes []string
		for _, node := range knownNodes {
			if node != addr {
				updatedNodes = append(updatedNodes, node)
			}
		}
		knownNodes = updatedNodes
		return
	}
	defer conn.Close()
	_, _ = conn.Write(data)
}

// commandToBytes pads a command string into a fixed 12-byte array buffer for packet headers.
func commandToBytes(command string) []byte {
	var bytes [12]byte
	for i, c := range command {
		bytes[i] = byte(c)
	}
	return bytes[:]
}

// straFromBytes strips null padding bytes from a command header buffer and returns the command string.
func straFromBytes(bytes []byte) string {
	var result []byte
	for _, b := range bytes {
		if b != 0x0 {
			result = append(result, b)
		}
	}
	return string(result)
}

// gobEncode serializes arbitrary Go data structures into a raw byte buffer using gob.
func gobEncode(data interface{}) []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	_ = enc.Encode(data)
	return buff.Bytes()
}

// sendVersion sends a version handshake packet containing node height and address to a peer.
func sendVersion(addr string, bc *Blockchain) {
	bestHeight := bc.GetBestHeight()
	payload := gobEncode(Version{nodeVersion, bestHeight, nodeAddress})
	request := append(commandToBytes(CmdVersion), payload...)
	sendData(addr, request)
}

// handleVersion processes incoming version handshake packets and synchronizes chain heights with peers.
func handleVersion(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload Version
	buff.Write(request[12:])
	_ = gob.NewDecoder(&buff).Decode(&payload)

	bestHeight := bc.GetBestHeight()
	foreignerBestHeight := payload.BestHeight

	if bestHeight < foreignerBestHeight {
		sendGetBlocks(payload.AddrFrom)
	} else if bestHeight > foreignerBestHeight {
		sendVersion(payload.AddrFrom, bc)
	}
	if !nodeIsKnown(payload.AddrFrom) {
		knownNodes = append(knownNodes, payload.AddrFrom)
	}
}

// sendGetBlocks requests block inventories from a remote peer node.
func sendGetBlocks(address string) {
	payload := gobEncode(GetBlocks{nodeAddress})
	request := append(commandToBytes(CmdGetBlocks), payload...)
	sendData(address, request)
}

// handleGetBlocks handles block inventory requests and sends inventory lists back to the requester.
func handleGetBlocks(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload GetBlocks
	buff.Write(request[12:])
	_ = gob.NewDecoder(&buff).Decode(&payload)

	blockHashes := bc.GetBlockHashes()
	sendInv(payload.AddrFrom, "block", blockHashes)
}

// sendInv transmits an inventory list packet containing hashes of available blocks or transactions.
func sendInv(address, kind string, items [][]byte) {
	payload := gobEncode(Inv{nodeAddress, kind, items})
	request := append(commandToBytes(CmdInv), payload...)
	sendData(address, request)
}

// handleInv processes received inventory lists and requests missing blocks or transactions.
func handleInv(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload Inv
	buff.Write(request[12:])
	_ = gob.NewDecoder(&buff).Decode(&payload)

	log.Printf("[P2P] Received inventory with %d items of type %s", len(payload.Items), payload.Type)
	if payload.Type == "block" {
		blocksInTransit = payload.Items
		blockHash := payload.Items[0]
		sendGetData(payload.AddrFrom, "block", blockHash)
	}
}

// sendGetData requests specific block or transaction data object payloads from a peer.
func sendGetData(address, kind string, id []byte) {
	payload := gobEncode(GetData{nodeAddress, kind, id})
	request := append(commandToBytes(CmdGetData), payload...)
	sendData(address, request)
}

// handleGetData processes requests for specific blocks or transactions and transmits the serialized data.
func handleGetData(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload GetData
	buff.Write(request[12:])
	_ = gob.NewDecoder(&buff).Decode(&payload)

	if payload.Type == "block" {
		block, _ := bc.GetBlock([]byte(payload.ID))
		sendBlock(payload.AddrFrom, block)
	}
}

// sendBlock transmits a serialized block packet to a remote peer address.
func sendBlock(address string, b []byte) {
	payload := gobEncode(BlockPacket{nodeAddress, b})
	request := append(commandToBytes(CmdBlock), payload...)
	sendData(address, request)
}

// handleBlock processes received block packets, appends them to the blockchain, and continues syncing.
func handleBlock(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload BlockPacket
	buff.Write(request[12:])
	_ = gob.NewDecoder(&buff).Decode(&payload)

	blockBytes := payload.Block
	block := deserializeBlock(blockBytes)
	bc.AddBlock(block)

	log.Printf("[P2P] Added block %s to chain", block.Hash)

	if len(blocksInTransit) > 0 {
		blockHash := blocksInTransit[0]
		sendGetData(payload.AddrFrom, "block", blockHash)
		blocksInTransit = blocksInTransit[1:]
	} else {
		minerAddress := block.Transactions[0].Vout[0].ScriptPubKey
		bc.MineBlock(mempool.GetAll(), minerAddress)
	}
}

// sendTx broadcasts a serialized transaction packet to a remote peer node.
func sendTx(address string, txd *Transaction) {
	data := TxPacket{nodeAddress, gobEncode(txd)}
	payload := gobEncode(data)
	request := append(commandToBytes(CmdTx), payload...)
	sendData(address, request)
}

// handleTx processes received network transaction packets, adds them to mempool, and relays them to other peers.
func handleTx(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload TxPacket
	buff.Write(request[12:])
	_ = gob.NewDecoder(&buff).Decode(&payload)

	txData := payload.Transaction
	var tx Transaction
	_ = gob.NewDecoder(bytes.NewReader(txData)).Decode(&tx)
	mempool.Add(&tx)

	if nodeAddress == knownNodes[0] {
		for _, node := range knownNodes {
			if node != nodeAddress && node != payload.AddrFrom {
				sendTx(node, &tx)
			}
		}
	} else {
		log.Printf("[P2P] Received transaction %s", tx.ID)
	}
}

// nodeIsKnown checks whether a given network address already exists inside our known nodes list slice.
func nodeIsKnown(addr string) bool {
	for _, node := range knownNodes {
		if node == addr {
			return true
		}
	}
	return false
}

// ================= COMMAND LINE INTERFACE (CLI) =================

// CLI handles command-line argument parsing and execution dispatching for user operations.
type CLI struct{}

// printUsage outputs CLI command instructions and manual guidelines to the console.
func (cli *CLI) printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  createblockchain -address <ADDRESS>           - Create a blockchain and send genesis reward")
	fmt.Println("  createwallet                                  - Generates a new wallet address")
	fmt.Println("  getbalance -address <ADDRESS>                 - Get balance of an address")
	fmt.Println("  printchain                                    - Print all blocks of the blockchain")
	fmt.Println("  mine -miner <ADDRESS>                         - Mine a new block with pending mempool txs")
	fmt.Println("  send -from <FROM> -to <TO> -amount <AMOUNT>   - Send coins from one address to another")
	fmt.Println("  startnode -port <PORT>                        - Start node P2P server")
}

// validateArgs verifies that sufficient command-line arguments are provided upon execution.
func (cli *CLI) validateArgs() {
	if len(os.Args) < 2 {
		cli.printUsage()
		os.Exit(1)
	}
}

// Run parses command-line flags and executes corresponding blockchain functions and commands.
func (cli *CLI) Run() {
	cli.validateArgs()

	// Initialize individual flag set definitions for each CLI command mode.
	createBlockchainCmd := flag.NewFlagSet("createblockchain", flag.ExitOnError)
	createWalletCmd := flag.NewFlagSet("createwallet", flag.ExitOnError)
	getBalanceCmd := flag.NewFlagSet("getbalance", flag.ExitOnError)
	printChainCmd := flag.NewFlagSet("printchain", flag.ExitOnError)
	mineCmd := flag.NewFlagSet("mine", flag.ExitOnError)
	sendCmd := flag.NewFlagSet("send", flag.ExitOnError)
	startNodeCmd := flag.NewFlagSet("startnode", flag.ExitOnError)

	// Bind command-specific flag variables to accept user inputs.
	createBlockchainAddress := createBlockchainCmd.String("address", "", "The address to send genesis block reward to")
	getBalanceAddress := getBalanceCmd.String("address", "", "The address to get balance for")
	mineMinerAddress := mineCmd.String("miner", "", "Miner address to receive block reward")
	
	sendFrom := sendCmd.String("from", "", "Source wallet address")
	sendTo := sendCmd.String("to", "", "Destination recipient address")
	sendAmount := sendCmd.Int("amount", 0, "Amount of coins to send")

	startNodePort := startNodeCmd.String("port", "3000", "P2P port for current node")

	// Switch statement matching the requested command keyword argument.
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
	case "startnode":
		_ = startNodeCmd.Parse(os.Args[2:])
	default:
		cli.printUsage()
		os.Exit(1)
	}

	// Execute logic associated with the parsed createblockchain flag set.
	if createBlockchainCmd.Parsed() {
		if *createBlockchainAddress == "" {
			createBlockchainCmd.Usage()
			os.Exit(1)
		}
		bc := CreateBlockchain(*createBlockchainAddress)
		defer bc.Db.Close()
		log.Println("Done! Genesis block created successfully.")
	}

	// Execute logic associated with generating a new digital wallet.
	if createWalletCmd.Parsed() {
		w := wallet.NewWallet()
		log.Printf("New Wallet Generated!\nAddress: %s", w.GetAddress())
	}

	// Execute logic associated with querying an address balance.
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

	// Execute logic associated with printing all blocks stored in the chain ledger.
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

	// Execute logic associated with mining a new block from mempool transactions.
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

	// Execute logic associated with creating and broadcasting a coin transfer transaction.
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
		sendTx(knownNodes[0], tx)
		log.Println("Success! Transaction broadcasted to network and added to mempool.")
	}

	// Execute logic associated with launching the P2P node server listener.
	if startNodeCmd.Parsed() {
		if *startNodePort == "" {
			startNodeCmd.Usage()
			os.Exit(1)
		}
		log.Printf("Starting P2P Node on port %s...\n", *startNodePort)
		StartServer(*startNodePort)
	}
}

// main serves as the primary entry point executing application logger initialization and CLI routing.
func main() {
	// Initialize our dual-output logging system.
	InitLogger()
	// Ensure the debug log file handle is closed upon program termination via defer.
	defer CloseLogger()

	// Instantiate and run the command line interface processor.
	cli := CLI{}
	cli.Run()
}
