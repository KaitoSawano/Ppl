// Package core handles the core blockchain logic including Proof-of-Work and Block management.
package core

import (
	"blockchain/transaction"
	"bytes"
	"encoding/json"
	"go.etcd.io/bbolt"
	"log"
)

const mempoolBucket = "mempool"

// Mempool manages pending transactions stored persistently in the database.
type Mempool struct {
	db *bbolt.DB
}

// NewMempool initializes a Mempool instance tied to the bbolt database.
func NewMempool(db *bbolt.DB) *Mempool {
	// Ensure the mempool bucket exists
	err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(mempoolBucket))
		return err
	})
	if err != nil {
		log.Panic(err)
	}

	return &Mempool{db: db}
}

// Add stores a new transaction persistently into the mempool bucket.
func (mp *Mempool) Add(tx *transaction.Transaction) {
	err := mp.db.Update(func(bTx *bbolt.Tx) error {
		b := bTx.Bucket([]byte(mempoolBucket))
		var encoded bytes.Buffer
		enc := json.NewEncoder(&encoded)
		_ = enc.Encode(tx)
		return b.Put([]byte(tx.ID), encoded.Bytes())
	})
	if err != nil {
		log.Panic(err)
	}
}

// GetAll retrieves all pending transactions currently stored in the mempool database.
func (mp *Mempool) GetAll() []*transaction.Transaction {
	var txs []*transaction.Transaction

	err := mp.db.View(func(bTx *bbolt.Tx) error {
		b := bTx.Bucket([]byte(mempoolBucket))
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var tx transaction.Transaction
			dec := json.NewDecoder(bytes.NewReader(v))
			_ = dec.Decode(&tx)
			txs = append(txs, &tx)
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return txs
}

// Clear removes successfully mined transactions from the mempool database.
func (mp *Mempool) Clear(minedTxs []*transaction.Transaction) {
	err := mp.db.Update(func(bTx *bbolt.Tx) error {
		b := bTx.Bucket([]byte(mempoolBucket))
		for _, tx := range minedTxs {
			if !tx.IsCoinbase() {
				_ = b.Delete([]byte(tx.ID))
			}
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}

// Size returns the total count of pending transactions in the mempool database.
func (mp *Mempool) Size() int {
	size := 0
	_ = mp.db.View(func(bTx *bbolt.Tx) error {
		b := bTx.Bucket([]byte(mempoolBucket))
		size = b.Stats().KeyN
		return nil
	})
	return size
}
