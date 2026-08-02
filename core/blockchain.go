// Package core handles the core blockchain logic including Proof-of-Work and Block management.
package core

import (
	"blockchain/transaction"
	"fmt"
	"time"
)

// Blockchain represents the main chain structure along with the local UTXO database set.
type Blockchain struct {
	Blocks  []*Block
	UTXOSet map[string]transaction.TXOutput
}

// NewBlockchain creates a new blockchain instance and mines the Genesis Block (Block 0).
func NewBlockchain(genesisAddress string) *Blockchain {
	bc := &Blockchain{
		Blocks:  []*Block{},
		UTXOSet: make(map[string]transaction.TXOutput),
	}

	cbtx := transaction.NewCoinbaseTX(genesisAddress, "Genesis Block - Initializing Network")
	genesisBlock := bc.CreateGenesisBlock(cbtx)
	bc.Blocks = append(bc.Blocks, genesisBlock)
	bc.updateUTXOSet(genesisBlock)

	return bc
}

// CreateGenesisBlock mines and returns the first block (Genesis Block) in the network.
func (bc *Blockchain) CreateGenesisBlock(coinbase *transaction.Transaction) *Block {
	block := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  []*transaction.Transaction{coinbase},
		PrevBlockHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Height:        0,
	}
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Nonce = nonce
	block.Hash = hash
	return block
}

// MineBlock processes and mines a new block using pending transactions from the mempool.
func (bc *Blockchain) MineBlock(mempool *Mempool, minerAddress string) *Block {
	// Ambil semua transaksi tertunda yang ada di mempool
	pendingTxs := mempool.GetAll()

	cbtx := transaction.NewCoinbaseTX(minerAddress, "")
	allTransactions := append([]*transaction.Transaction{cbtx}, pendingTxs...)

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

	// Bersihkan transaksi yang sudah sukses dimasukkan ke dalam blok dari mempool
	mempool.Clear(pendingTxs)

	return newBlock
}

// updateUTXOSet updates the local UTXO database status by removing spent inputs and adding new outputs.
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

// GetBalance calculates the total accumulated unspent coin balance for a specific address.
func (bc *Blockchain) GetBalance(address string) int {
	balance := 0
	for _, out := range bc.UTXOSet {
		if out.ScriptPubKey == address {
			balance += out.Value
		}
	}
	return balance
}

// FindSpendableOutputs finds unspent outputs for an address until the required amount is met.
func (bc *Blockchain) FindSpendableOutputs(address string, amount int) (int, map[string]int) {
	unspentOutputs := make(map[string]int)
	accumulated := 0

	for txid, out := range bc.UTXOSet {
		if out.ScriptPubKey == address {
			accumulated += out.Value
			var realTxid string
			var vout int
			_, _ = fmt.Sscanf(txid, "%s_%d", &realTxid, &vout)
			unspentOutputs[realTxid] = vout
			if accumulated >= amount {
				break
			}
		}
	}
	return accumulated, unspentOutputs
}

// NewUTXOTransaction creates a new transaction from sender to recipient with change handling.
func (bc *Blockchain) NewUTXOTransaction(from, to string, amount int) (*transaction.Transaction, error) {
	var inputs []transaction.TXInput
	var outputs []transaction.TXOutput

	acc, validOutputs := bc.FindSpendableOutputs(from, amount)

	if acc < amount {
		return nil, fmt.Errorf("error: insufficient funds")
	}

	// Build inputs
	for txid, vout := range validOutputs {
		input := transaction.TXInput{Txid: txid, Vout: vout, Signature: nil, PubKey: []byte(from)}
		inputs = append(inputs, input)
	}

	// Build a recipient output
	outputs = append(outputs, transaction.TXOutput{Value: amount, ScriptPubKey: to})

	// Build a change output if there is leftover balance
	if acc > amount {
		outputs = append(outputs, transaction.TXOutput{Value: acc - amount, ScriptPubKey: from})
	}

	tx := &transaction.Transaction{ID: "", Vin: inputs, Vout: outputs}
	tx.ID = tx.Hash()
	return tx, nil
}
