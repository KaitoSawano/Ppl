package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"golang.org/x/crypto/sha3"
)

// Types definition following modular data structures
type (
	TXInput struct {
		Txid      string
		Vout      int
		Signature []byte
		PubKey    []byte
	}

	TXOutput struct {
		Value        int
		ScriptPubKey string
	}

	Transaction struct {
		ID   string
		Vin  []TXInput
		Vout []TXOutput
	}

	Block struct {
		Timestamp     int64
		Transactions  []*Transaction
		PrevBlockHash string
		Hash          string
		Nonce         int
		Height        int
	}

	Blockchain struct {
		Blocks  []*Block
		UTXOSet map[string]TXOutput
	}

	ProofOfWork struct {
		block  *Block
		target *big.Int
	}
)

const (
	TargetBits = 12
	Subsidy    = 50
)

// HashKeccak256 generates a hexadecimal hash string using SHA-3 (Keccak-256).
func HashKeccak256(b []byte) string {
	h := sha3.New256()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Hash generates a unique identifier for a transaction based on its encoded data.
func (tx *Transaction) Hash() string {
	var encoded bytes.Buffer
	enc := json.NewEncoder(&encoded)
	_ = enc.Encode(tx)
	return HashKeccak256(encoded.Bytes())
}

// IsCoinbase checks if a transaction is a coinbase transaction.
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Vin) == 1 && tx.Vin[0].Txid == "" && tx.Vin[0].Vout == -1
}

// NewProofOfWork initializes a PoW instance for the given block.
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-TargetBits))
	return &ProofOfWork{block: b, target: target}
}

// prepareData aggregates block fields into a byte slice for hashing.
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
			intToHex(int64(TargetBits)),
			intToHex(int64(nonce)),
		},
		[]byte{},
	)
	return data
}

// Run executes the mining loop to find a valid block hash.
func (pow *ProofOfWork) Run() (int, string) {
	var hashInt big.Int
	var hash string
	nonce := 0

	fmt.Printf("Mining block at height %d...\n", pow.block.Height)
	for nonce < math.MaxInt64 {
		data := pow.prepareData(nonce)
		hash = HashKeccak256(data)
		hashInt.SetString(hash, 16)

		if hashInt.Cmp(pow.target) == -1 {
			break
		}
		nonce++
	}
	return nonce, hash
}

// intToHex converts an integer to a hex byte slice.
func intToHex(n int64) []byte {
	return []byte(fmt.Sprintf("%x", n))
}

// NewCoinbaseTX creates a coinbase transaction rewarding the miner.
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

// NewUTXOTransaction creates a standard value transfer transaction between addresses.
func NewUTXOTransaction(sender, recipient string, amount int, bc *Blockchain) (*Transaction, error) {
	var inputs []TXInput
	var outputs []TXOutput

	acc, validOutputs := bc.FindSpendableOutputs(sender, amount)

	if acc < amount {
		return nil, errors.New("error: insufficient funds")
	}

	for txid, outs := range validOutputs {
		for _, outIdx := range outs {
			input := TXInput{Txid: txid, Vout: outIdx, Signature: nil, PubKey: []byte(sender)}
			inputs = append(inputs, input)
		}
	}

	outputs = append(outputs, TXOutput{Value: amount, ScriptPubKey: recipient})
	if acc > amount {
		outputs = append(outputs, TXOutput{Value: acc - amount, ScriptPubKey: sender})
	}

	tx := Transaction{ID: "", Vin: inputs, Vout: outputs}
	tx.ID = tx.Hash()
	return &tx, nil
}

// FindSpendableOutputs finds unspent outputs for an address until the amount is met.
func (bc *Blockchain) FindSpendableOutputs(address string, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	accumulated := 0

	for key, out := range bc.UTXOSet {
		if out.ScriptPubKey == address {
			var txid string
			var outIdx int
			_, _ = fmt.Sscanf(key, "%s_%d", &txid, &outIdx)

			accumulated += out.Value
			unspentOutputs[txid] = append(unspentOutputs[txid], outIdx)

			if accumulated >= amount {
				break
			}
		}
	}

	return accumulated, unspentOutputs
}

// NewBlockchain creates a new blockchain instance with a genesis block.
func NewBlockchain(genesisAddress string) *Blockchain {
	bc := &Blockchain{
		Blocks:  []*Block{},
		UTXOSet: make(map[string]TXOutput),
	}

	cbtx := NewCoinbaseTX(genesisAddress, "Genesis Block - Initializing Network")
	genesisBlock := bc.CreateGenesisBlock(cbtx)
	bc.Blocks = append(bc.Blocks, genesisBlock)
	bc.updateUTXOSet(genesisBlock)

	return bc
}

// CreateGenesisBlock mines and returns the first block in the chain.
func (bc *Blockchain) CreateGenesisBlock(coinbase *Transaction) *Block {
	block := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  []*Transaction{coinbase},
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Height:        0,
	}
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Nonce = nonce
	block.Hash = hash
	return block
}

// MineBlock mines a new block containing transactions and updates the UTXO set.
func (bc *Blockchain) MineBlock(transactions []*Transaction, minerAddress string) *Block {
	cbtx := NewCoinbaseTX(minerAddress, "")
	allTransactions := append([]*Transaction{cbtx}, transactions...)

	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  allTransactions,
		PrevBlockHash: prevBlock.Hash,
		Height:        prevBlock.Height + 1,
	}

	pow := NewProofOfWork(newBlock)
	nonce, hash := pow.Run()
	newBlock.Nonce = nonce
	newBlock.Hash = hash

	bc.Blocks = append(bc.Blocks, newBlock)
	bc.updateUTXOSet(newBlock)
	return newBlock
}

// updateUTXOSet updates the local database state with spent and new outputs.
func (bc *Blockchain) updateUTXOSet(block *Block) {
	for _, tx := range block.Transactions {
		if !tx.IsCoinbase() {
			for _, in := range tx.Vin {
				key := fmt.Sprintf("%s_%d", in.Txid, in.Vout)
				delete(bc.UTXOSet, key)
			}
		}
		for outIdx, out := range tx.Vout {
			key := fmt.Sprintf("%s_%d", tx.ID, outIdx)
			bc.UTXOSet[key] = out
		}
	}
}

// GetBalance calculates the total unspent balance for a given address.
func (bc *Blockchain) GetBalance(address string) int {
	balance := 0
	for _, out := range bc.UTXOSet {
		if out.ScriptPubKey == address {
			balance += out.Value
		}
	}
	return balance
}

func main() {
	fmt.Println("Starting PoW Blockchain Initialization (Keccak-256 + UTXO)...")

	minerAddress := "Wallet_Dev"
	userAddress := "Wallet_User"
	bc := NewBlockchain(minerAddress)

	fmt.Printf("Genesis Block Successfully Mined!\n")
	fmt.Printf("Balance of '%s': %d coins\n\n", minerAddress, bc.GetBalance(minerAddress))

	fmt.Println("--- Mining Block 1 (Reward to Dev) ---")
	bc.MineBlock([]*Transaction{}, minerAddress)
	fmt.Printf("Balance of '%s' after Block 1: %d coins\n\n", minerAddress, bc.GetBalance(minerAddress))

	fmt.Println("--- Executing Value Transfer: Dev sends 20 coins to User ---")
	tx, err := NewUTXOTransaction(minerAddress, userAddress, 20, bc)
	if err != nil {
		fmt.Printf("Transaction failed: %v\n", err)
		return
	}

	fmt.Println("--- Mining Block 2 (Including Transfer Transaction) ---")
	bc.MineBlock([]*Transaction{tx}, minerAddress)

	fmt.Printf("Balance of '%s': %d coins\n", minerAddress, bc.GetBalance(minerAddress))
	fmt.Printf("Balance of '%s': %d coins\n\n", userAddress, bc.GetBalance(userAddress))

	fmt.Println("--- Blockchain Chain Information Summary ---")
	for _, block := range bc.Blocks {
		fmt.Printf("Block Height : %d\n", block.Height)
		fmt.Printf("Prev. Hash   : %s\n", block.PrevBlockHash)
		fmt.Printf("Block Hash   : %s\n", block.Hash)
		fmt.Printf("Nonce        : %d\n", block.Nonce)
		fmt.Printf("Tx Count     : %d\n", len(block.Transactions))
		fmt.Println("--------------------------------------------------")
	}
}
