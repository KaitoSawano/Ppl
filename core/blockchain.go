// Package core handles the core blockchain logic including Proof-of-Work, Block management, and BoltDB storage.
package core

import (
	"blockchain/transaction"
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"time"

	"go.etcd.io/bbolt"
)

// Blockchain represents the blockchain database and the tip (hash of the latest block).
type Blockchain struct {
	Tip []byte
	Db  *bbolt.DB
}

// Block represents a single block structure linked within the blockchain.
type Block struct {
	Timestamp     int64
	Transactions  []*transaction.Transaction
	PrevBlockHash string
	Hash          string
	Nonce         int
	Height        int
}

// CreateBlockchain creates a new blockchain DB, mines the Genesis Block, and stores it.
func CreateBlockchain(genesisAddress string) *Blockchain {
	dbFile := "blockchain.db"
	db, err := bbolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	var tip []byte

	err = db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		if b == nil {
			cbtx := transaction.NewCoinbaseTX(genesisAddress, "Genesis Block - Initializing Network")
			genesis := NewGenesisBlock(cbtx)
			b, err := tx.CreateBucket([]byte("blocks"))
			if err != nil {
				log.Panic(err)
			}
			err = b.Put([]byte(genesis.Hash), genesis.Serialize())
			if err != nil {
				log.Panic(err)
			}
			err = b.Put([]byte("l"), []byte(genesis.Hash))
			if err != nil {
				log.Panic(err)
			}
			tip = []byte(genesis.Hash)
		} else {
			tip = b.Get([]byte("l"))
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return &Blockchain{Tip: tip, Db: db}
}

// NewGenesisBlock creates and returns the first block (Genesis Block).
func NewGenesisBlock(coinbase *transaction.Transaction) *Block {
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

// MineBlock mines a new block containing pending transactions from the mempool and saves it to BoltDB.
func (bc *Blockchain) MineBlock(mempool *Mempool, minerAddress string) *Block {
	pendingTxs := mempool.GetAll()

	cbtx := transaction.NewCoinbaseTX(minerAddress, "")
	allTransactions := append([]*transaction.Transaction{cbtx}, pendingTxs...)

	var lastHeight int
	var lastHash string

	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		lastHashBytes := b.Get([]byte("l"))
		blockData := b.Get(lastHashBytes)
		lastBlock := DeserializeBlock(blockData)
		lastHeight = lastBlock.Height
		lastHash = lastBlock.Hash
		return nil
	})

	newBlock := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  allTransactions,
		PrevBlockHash: lastHash,
		Height:        lastHeight + 1,
	}

	pow := NewProofOfWork(newBlock)
	nonce, hash := pow.Run()
	newBlock.Nonce = nonce
	newBlock.Hash = hash

	bc.Db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		err := b.Put([]byte(newBlock.Hash), newBlock.Serialize())
		if err != nil {
			log.Panic(err)
		}
		err = b.Put([]byte("l"), []byte(newBlock.Hash))
		if err != nil {
			log.Panic(err)
		}
		bc.Tip = []byte(newBlock.Hash)
		return nil
	})

	mempool.Clear(pendingTxs)
	fmt.Printf("[PoW] Mining block at height %d (Difficulty: 12)...\n", newBlock.Height)
	fmt.Println("Success! Block mined.")

	return newBlock
}

// Serialize converts a Block into a byte slice.
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)
	err := encoder.Encode(b)
	if err != nil {
		log.Panic(err)
	}
	return result.Bytes()
}

// DeserializeBlock converts a byte slice back into a Block instance.
func DeserializeBlock(d []byte) *Block {
	var block Block
	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}
	return &block
}

// GetBalance calculates the total unspent balance for an address by scanning all blocks in the database.
func (bc *Blockchain) GetBalance(address string) int {
	balance := 0
	UTXOs := bc.FindUTXO(address)

	for _, out := range UTXOs {
		balance += out.Value
	}
	return balance
}

// FindUTXO finds all unspent transaction outputs for a specific address.
func (bc *Blockchain) FindUTXO(address string) []transaction.TXOutput {
	var unspentUTXOs []transaction.TXOutput
	spentTXOs := make(map[string][]int)

	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		cursor := b.Cursor()

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := DeserializeBlock(v)

			for _, tx := range block.Transactions {
				if !tx.IsCoinbase() {
					for _, in := range tx.Vin {
						spentTXOs[in.Txid] = append(spentTXOs[in.Txid], in.Vout)
					}
				}
			}
		}

		mempool := NewMempool(bc.Db)
		pendingTxs := mempool.GetAll()
		for _, tx := range pendingTxs {
			if !tx.IsCoinbase() {
				for _, in := range tx.Vin {
					spentTXOs[in.Txid] = append(spentTXOs[in.Txid], in.Vout)
				}
			}
		}

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := DeserializeBlock(v)

			for _, tx := range block.Transactions {
				txID := tx.ID

				for outIdx, out := range tx.Vout {
					if out.ScriptPubKey == address {
						isSpent := false
						if spentTXOs[txID] != nil {
							for _, spentOutIdx := range spentTXOs[txID] {
								if spentOutIdx == outIdx {
									isSpent = true
									break
								}
							}
						}
						if !isSpent {
							unspentUTXOs = append(unspentUTXOs, out)
						}
					}
				}
			}
		}

		for _, tx := range pendingTxs {
			txID := tx.ID
			for outIdx, out := range tx.Vout {
				if out.ScriptPubKey == address {
					isSpent := false
					if spentTXOs[txID] != nil {
						for _, spentOutIdx := range spentTXOs[txID] {
							if spentOutIdx == outIdx {
								isSpent = true
								break
							}
						}
					}
					if !isSpent {
						unspentUTXOs = append(unspentUTXOs, out)
					}
				}
			}
		}

		return nil
	})

	return unspentUTXOs
}

// FindSpendableOutputs finds spendable outputs and accumulates enough value for a transaction.
func (bc *Blockchain) FindSpendableOutputs(address string, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	accumulated := 0
	spentTXOs := make(map[string][]int)

	bc.Db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("blocks"))
		cursor := b.Cursor()

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := DeserializeBlock(v)

			for _, tx := range block.Transactions {
				if !tx.IsCoinbase() {
					for _, in := range tx.Vin {
						spentTXOs[in.Txid] = append(spentTXOs[in.Txid], in.Vout)
					}
				}
			}
		}

		mempool := NewMempool(bc.Db)
		pendingTxs := mempool.GetAll()
		for _, tx := range pendingTxs {
			if !tx.IsCoinbase() {
				for _, in := range tx.Vin {
					spentTXOs[in.Txid] = append(spentTXOs[in.Txid], in.Vout)
				}
			}
		}

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "l" {
				continue
			}
			block := DeserializeBlock(v)

			for _, tx := range block.Transactions {
				txID := tx.ID

				for outIdx, out := range tx.Vout {
					if out.ScriptPubKey == address {
						isSpent := false
						if spentTXOs[txID] != nil {
							for _, spentOutIdx := range spentTXOs[txID] {
								if spentOutIdx == outIdx {
									isSpent = true
									break
								}
							}
						}

						if !isSpent {
							accumulated += out.Value
							unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
							if accumulated >= amount {
								return nil
							}
						}
					}
				}
			}
		}

		for _, tx := range pendingTxs {
			txID := tx.ID
			for outIdx, out := range tx.Vout {
				if out.ScriptPubKey == address {
					isSpent := false
					if spentTXOs[txID] != nil {
						for _, spentOutIdx := range spentTXOs[txID] {
							if spentOutIdx == outIdx {
								isSpent = true
								break
							}
						}
					}

					if !isSpent {
						accumulated += out.Value
						unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
						if accumulated >= amount {
							return nil
						}
					}
				}
			}
		}

		return nil
	})

	return accumulated, unspentOutputs
}

// NewUTXOTransaction creates a new transaction from sender to recipient with proper UTXO tracking.
func (bc *Blockchain) NewUTXOTransaction(from, to string, amount int) (*transaction.Transaction, error) {
	var inputs []transaction.TXInput
	var outputs []transaction.TXOutput

	acc, validOutputs := bc.FindSpendableOutputs(from, amount)

	if acc < amount {
		return nil, fmt.Errorf("error: insufficient funds")
	}

	for txid, outs := range validOutputs {
		for _, out := range outs {
			input := transaction.TXInput{Txid: txid, Vout: out, Signature: nil, PubKey: []byte(from)}
			inputs = append(inputs, input)
		}
	}

	outputs = append(outputs, transaction.TXOutput{Value: amount, ScriptPubKey: to})
	if acc > amount {
		outputs = append(outputs, transaction.TXOutput{Value: acc - amount, ScriptPubKey: from})
	}

	tx := &transaction.Transaction{ID: "", Vin: inputs, Vout: outputs}
	tx.ID = tx.Hash()
	return tx, nil
}
