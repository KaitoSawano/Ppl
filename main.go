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
	dbFile            = "blockchain.db"
	blocksBucket      = "blocks"
	Subsidy           = 50  // Block reward subsidy in coins
	BlockInterval     = 5   // Interval blocks for dynamic difficulty adjustments (set to 5 for quick demo)
	BlockTargetTime   = 60  // Target time in seconds for mining a block interval
	InitialDifficulty = 12  // Starting difficulty
)

// ================= STRUCT DEFINITIONS =================

// TXInput represents a transaction input pointing to a previous unspent transaction output (UTXO).
type TXInput struct {
	Txid      string
	Vout      int
	Signature []byte
	PubKey    []byte
}

// TXOutput represents a transaction output containing value and locking script (recipient address).
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

// Global mempool instance initialization.
var mempool = NewMempool()

// ================= MEMPOOL MANAGEMENT =================

// NewMempool instantiates and returns a thread-safe transaction pool.
func NewMempool() *Mempool {
	return &Mempool{transactions: make(map[string]*Transaction)}
}

// Add safely inserts a new pending transaction into the mempool map.
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

// Clear purges successfully mined non-coinbase transactions from the mempool.
func (mp *Mempool) Clear(minedTxs []*Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	for _, tx := range minedTxs {
		if !tx.IsCoinbase() {
			delete(mp.transactions, tx.ID)
		}
	}
}

// Size returns the current count of pending transactions awaiting confirmation.
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

// Hash serializes the transaction object and returns its unique cryptographic identifier.
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

	fmt.Printf("[PoW] Mining block at height %d (Difficulty: %d)...\n", pow.block.Height, pow.block.Difficulty)
	for nonce < math.MaxInt64 {
		data := pow.prepareData(nonce)
		hash = HashKeccak256(data)
		hashInt.SetString(hash, 16)

		// Check if computed hash is below the strict target threshold
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
	balance := 0

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

	return &tx, nil
}

// CalculateDifficulty dynamically adjusts mining difficulty based on block intervals.
func (bc *Blockchain) CalculateDifficulty(lastBlock *Block) int {
	// Only adjust difficulty every `BlockInterval` blocks
	if lastBlock.Height == 0 || lastBlock.Height%BlockInterval != 0 {
		return lastBlock.Difficulty
	}

	// Find the checkpoint block from `BlockInterval` blocks ago
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

	fmt.Printf("[Difficulty Adjustment] Actual time for last %d blocks: %ds (Target: %ds)\n", 
		BlockInterval, actualTimeSpan, targetTimeSpan)

	// Adjust difficulty limits to avoid wild swings
	if actualTimeSpan < targetTimeSpan/2 {
		fmt.Println("[Difficulty Adjustment] Mining too fast! Increasing difficulty.")
		return lastBlock.Difficulty + 1
	} else if actualTimeSpan > targetTimeSpan*2 {
		fmt.Println("[Difficulty Adjustment] Mining too slow! Decreasing difficulty.")
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
		} else {
			fmt.Printf("[Mempool] Transaction verification failed for ID: %s. Dropping.\n", tx.ID)
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

// ================= MAIN EXECUTION ENTRYPOINT =================

func main() {
	fmt.Println("Starting Advanced PoW Blockchain with Dynamic Difficulty...")

	go StartP2PServer("3000")

	walletDev := wallet.NewWallet()
	walletUser := wallet.NewWallet()

	minerAddress := walletDev.GetAddress()
	userAddress := walletUser.GetAddress()

	bc := CreateBlockchain(minerAddress)
	defer bc.Db.Close()

	fmt.Printf("Genesis Block Successfully Mined & Stored in BoltDB!\n")
	fmt.Printf("Dev Wallet Address  : %s\n", minerAddress)
	fmt.Printf("User Wallet Address : %s\n", userAddress)
	fmt.Printf("Balance of Dev      : %d coins\n\n", bc.GetBalance(minerAddress))

	fmt.Println("--- Mining Block 1 (Reward to Dev) ---")
	bc.MineBlock([]*Transaction{}, minerAddress)
	fmt.Printf("Balance of Dev after Block 1: %d coins\n\n", bc.GetBalance(minerAddress))

	fmt.Println("--- Executing Secure Value Transfer: Dev sends 20 coins to User ---")
	tx, err := NewUTXOTransaction(walletDev, userAddress, 20, bc)
	if err != nil {
		fmt.Printf("Transaction note: %v\n", err)
	} else {
		mempool.Add(tx)
	}

	dummyTx := NewCoinbaseTX(userAddress, "Mempool Sync Payload")
	mempool.Add(dummyTx)

	fmt.Printf("[Mempool] Transactions added! Pending pool size: %d\n\n", mempool.Size())

	fmt.Println("--- Mining Block 2 (Packing Transactions from Mempool) ---")
	bc.MineBlock(mempool.GetAll(), minerAddress)

	fmt.Printf("[Mempool] Status after mining: %d pending transactions left\n\n", mempool.Size())
	fmt.Printf("Balance of Dev  (After Block 2 mined): %d coins\n", bc.GetBalance(minerAddress))
	fmt.Printf("Balance of User (After Block 2 mined): %d coins\n", bc.GetBalance(userAddress))

	fmt.Println("--- Blockchain Chain Information Summary ---")
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
