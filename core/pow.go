// Package core handles the core blockchain logic including Proof-of-Work and Block management.
package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// TargetBits defines the mining difficulty target.
const TargetBits = 12

// ProofOfWork represents the structure for the consensus mining process.
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// HashKeccak256 generates a hexadecimal hash string using the SHA-3 (Keccak-256) algorithm.
func HashKeccak256(b []byte) string {
	h := sha3.New256()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// NewProofOfWork initializes a new Proof-of-Work instance for a given block.
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-TargetBits))
	return &ProofOfWork{block: b, target: target}
}

// prepareData aggregates block attributes into a byte slice before hashing.
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

// Run executes the mining loop to find a valid nonce matching the difficulty target.
func (pow *ProofOfWork) Run() (int, string) {
	var hashInt big.Int
	var hash string
	nonce := 0

	fmt.Printf("Mining block at height %d...\n", pow.block.Height)
	for nonce < math.MaxInt64 {
		data := pow.prepareData(nonce)
		hash = HashKeccak256(data)
		hashInt.SetString(hash, 16)

		// Check if the hash is less than the difficulty target
		if hashInt.Cmp(pow.target) == -1 {
			break
		}
		nonce++
	}
	return nonce, hash
}

// intToHex converts an integer (int64) into a hexadecimal byte slice representation.
func intToHex(n int64) []byte {
	return []byte(fmt.Sprintf("%x", n))
}
