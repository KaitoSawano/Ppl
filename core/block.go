package core

import "blockchain/transaction"

// Block represents a single block structure linked within the blockchain.
type Block struct {
	Timestamp     int64
	Transactions  []*transaction.Transaction
	PrevBlockHash string
	Hash          string
	Nonce         int
	Height        int
}
