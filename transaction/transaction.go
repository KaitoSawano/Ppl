// Package transaction manages transaction data structures, inputs/outputs, and coin rewards.
package transaction

import (
	"bytes"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// TXInput represents a transaction input (reference to a previous output).
type TXInput struct {
	Txid      string
	Vout      int
	Signature []byte
	PubKey    []byte
}

// TXOutput represents a transaction output (value amount and recipient address script).
type TXOutput struct {
	Value        int
	ScriptPubKey string
}

// Transaction represents a single transaction object in the network.
type Transaction struct {
	ID   string
	Vin  []TXInput
	Vout []TXOutput
}

// HashKeccak256 generates a SHA-3 based hexadecimal hash string.
func HashKeccak256(b []byte) string {
	h := sha3.New256()
	h.Write(b)
	return hexEncodeToString(h.Sum(nil))
}

// hexEncodeToString converts a byte slice to a hexadecimal string format.
func hexEncodeToString(b []byte) string {
	return fmt.Sprintf("%x", b)
}

// Hash creates a unique identifier (ID) for a transaction based on its encoded data.
func (tx *Transaction) Hash() string {
	var encoded bytes.Buffer
	enc := json.NewEncoder(&encoded)
	_ = enc.Encode(tx)
	
	h := sha3.New256()
	h.Write(encoded.Bytes())
	return fmt.Sprintf("%x", h.Sum(nil))
}

// IsCoinbase checks if the transaction is a coinbase transaction (miner reward).
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Vin) == 1 && tx.Vin[0].Txid == "" && tx.Vin[0].Vout == -1
}

// Subsidy defines the fixed coin reward amount for each successfully mined block.
const Subsidy = 50

// NewCoinbaseTX creates a special reward transaction for the miner at the start of a new block.
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
