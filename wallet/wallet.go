// Package wallet handles cryptographic key generation, address creation, and digital signing.
package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/big"
)

// Wallet stores private and public cryptographic keys.
type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

// NewWallet generates a new wallet instance with a fresh key pair.
func NewWallet() *Wallet {
	private, public := newKeyPair()
	return &Wallet{PrivateKey: *private, PublicKey: public}
}

// newKeyPair generates an ECDSA key pair using elliptic curve.
func newKeyPair() (*ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)
	return private, pubKey
}

// GetAddress menghasilkan string alamat dengan kustom prefix "gnx1"
func (w *Wallet) GetAddress() string {
	pubKeyHash := HashPubKey(w.PublicKey)
	address := "gnx" + hex.EncodeToString(pubKeyHash[:16])
	return address
}

// GetAddressFromPubKey mengekstrak alamat langsung dari public key byte
func GetAddressFromPubKey(pubKey []byte) string {
	pubKeyHash := HashPubKey(pubKey)
	return "gnx" + hex.EncodeToString(pubKeyHash[:16])
}

// HashPubKey hashes the public key using SHA-256.
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)
	h := sha256.New()
	h.Write(publicSHA256[:])
	return h.Sum(nil)[:20]
}

// Sign menghasilkan tanda tangan digital dari hash data
func (w *Wallet) Sign(hash []byte) []byte {
	r, s, err := ecdsa.Sign(rand.Reader, &w.PrivateKey, hash)
	if err != nil {
		log.Panic(err)
	}
	signature := append(r.Bytes(), s.Bytes()...)
	return signature
}

// Verify mengecek keabsahan tanda tangan digital
func Verify(pubKey, sig []byte, hash []byte) bool {
	curve := elliptic.P256()
	r := big.Int{}
	s := big.Int{}
	sigLen := len(sig)
	r.SetBytes(sig[:(sigLen / 2)])
	s.SetBytes(sig[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(pubKey)
	x.SetBytes(pubKey[:(keyLen / 2)])
	y.SetBytes(pubKey[(keyLen / 2):])

	rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	return ecdsa.Verify(&rawPubKey, hash, &r, &s)
}
