package transaction

import (
	"errors"
	"fmt"
)

// UTXOSetHolder defines the interface contract for UTXO set storage.
type UTXOSetHolder interface {
	GetUTXOSet() map[string]TXOutput
}

// FindSpendableOutputs scans available UTXOs to cover the transfer amount from a specific address.
func FindSpendableOutputs(utxoSet map[string]TXOutput, address string, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	accumulated := 0

	for key, out := range utxoSet {
		if out.ScriptPubKey == address {
			var txid string
			var outIdx int
			_, _ = fmt.Sscanf(key, "%s_%d", &txid, &outIdx)

			accumulated += out.Value
			unspentOutputs[txid] = append(unspentOutputs[txid], outIdx)

			// Stop scanning if accumulated balance reaches the target amount
			if accumulated >= amount {
				break
			}
		}
	}

	return accumulated, unspentOutputs
}

// NewUTXOTransaction creates a new value transfer transaction between a sender and recipient.
func NewUTXOTransaction(sender, recipient string, amount int, utxoSet map[string]TXOutput) (*Transaction, error) {
	var inputs []TXInput
	var outputs []TXOutput

	acc, validOutputs := FindSpendableOutputs(utxoSet, sender, amount)

	// Balance validation: ensure sender has sufficient funds
	if acc < amount {
		return nil, errors.New("error: insufficient funds")
	}

	// Construct transaction inputs from found UTXOs
	for txid, outs := range validOutputs {
		for _, outIdx := range outs {
			input := TXInput{Txid: txid, Vout: outIdx, Signature: nil, PubKey: []byte(sender)}
			inputs = append(inputs, input)
		}
	}

	// Add main output for the recipient
	outputs = append(outputs, TXOutput{Value: amount, ScriptPubKey: recipient})
	
	// If balance exceeds the sent amount, return the remainder as change back to the sender
	if acc > amount {
		outputs = append(outputs, TXOutput{Value: acc - amount, ScriptPubKey: sender})
	}

	tx := Transaction{ID: "", Vin: inputs, Vout: outputs}
	tx.ID = tx.Hash()
	return &tx, nil
}
