package core

import (
	"blockchain/transaction"
	"sync"
)

// Mempool manages pending transactions waiting to be mined into a block.
type Mempool struct {
	mu           sync.Mutex
	transactions map[string]*transaction.Transaction
}

// NewMempool initializes and returns a new Mempool instance.
func NewMempool() *Mempool {
	return &Mempool{
		transactions: make(map[string]*transaction.Transaction),
	}
}

// Add adds a new transaction to the mempool.
func (mp *Mempool) Add(tx *transaction.Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.transactions[tx.ID] = tx
}

// GetAll returns all pending transactions currently in the mempool.
func (mp *Mempool) GetAll() []*transaction.Transaction {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	var txs []*transaction.Transaction
	for _, tx := range mp.transactions {
		txs = append(txs, tx)
	}
	return txs
}

// Clear removes mined transactions from the mempool.
func (mp *Mempool) Clear(minedTxs []*transaction.Transaction) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	for _, tx := range minedTxs {
		if !tx.IsCoinbase() {
			delete(mp.transactions, tx.ID)
		}
	}
}

// Size returns the number of pending transactions in the mempool.
func (mp *Mempool) Size() int {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	return len(mp.transactions)
}
