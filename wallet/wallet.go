// Package wallet handles cryptographic key generation, address creation, and digital signing.
package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"os"
	"sync"
)

const walletFile = "wallet.dat"

// Wallet stores private key bytes and public key bytes.
type Wallet struct {
	PrivateKey []byte
	PublicKey  []byte
}

// Wallets stores a collection of wallets mapped by their address string.
type Wallets struct {
	Wallets map[string]*Wallet
	mu      sync.Mutex
}

// NewWallet generates a new wallet instance with a fresh key pair, saves it, and returns it.
func NewWallet() *Wallet {
	private, public := newKeyPair()
	privBytes := private.D.Bytes()
	w := &Wallet{PrivateKey: privBytes, PublicKey: public}

	ws, _ := LoadWallets()
	ws.Wallets[w.GetAddress()] = w
	ws.SaveFile()

	return w
}

// LoadWallets loads all saved wallets from the local wallet file.
func LoadWallets() (*Wallets, error) {
	wallets := &Wallets{}
	wallets.Wallets = make(map[string]*Wallet)

	if _, err := os.Stat(walletFile); os.IsNotExist(err) {
		return wallets, err
	}

	fileContent, err := os.ReadFile(walletFile)
	if err != nil {
		return nil, err
	}

	var decodedWallets Wallets
	decoder := gob.NewDecoder(bytes.NewReader(fileContent))
	err = decoder.Decode(&decodedWallets)
	if err != nil {
		return nil, err
	}

	wallets.Wallets = decodedWallets.Wallets
	return wallets, nil
}

// SaveFile serializes and saves the current collection of wallets to disk.
func (ws *Wallets) SaveFile() {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	var content bytes.Buffer
	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(ws)
	if err != nil {
		log.Panic(err)
	}

	err = os.WriteFile(walletFile, content.Bytes(), 0644)
	if err != nil {
		log.Panic(err)
	}
}

// GetWalletByAddress retrieves an existing wallet instance matching the provided address string.
func GetWalletByAddress(address string) (*Wallet, error) {
	ws, err := LoadWallets()
	if err != nil {
		return nil, err
	}

	wallet, exists := ws.Wallets[address]
	if !exists {
		return nil, errors.New("wallet with specified address not found")
	}

	return wallet, nil
}

// GetPrivateKey reconstructs and returns the *ecdsa.PrivateKey from stored bytes.
func (w *Wallet) GetPrivateKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	d := big.Int{}
	d.SetBytes(w.PrivateKey)
	
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: &d,
	}

	privKeyBytes := w.PrivateKey
	if len(privKeyBytes) < 32 {
		paddedBytes := make([]byte, 32)
		copy(paddedBytes[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = paddedBytes
	}

	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(privKeyBytes)
	return privKey
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

// GetAddress menghasilkan string alamat dengan kustom prefix "gnx"
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
	privKey := w.GetPrivateKey()
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash)
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
