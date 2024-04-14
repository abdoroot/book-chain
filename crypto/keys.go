package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
)

const (
	PrvKeyLen = 64
	PubKeyLen = 32
	AddrLen   = 20
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

func NewPrivateKeyFromSeed(seed []byte) PrivateKey {
	if len(seed) != 32 {
		panic("Key Must be 32 byte")
	}
	pks := PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
	return pks
}

func NewPrivateKeyFromString(keyPass string) PrivateKey {
	seed := make([]byte, 32)
	copy(seed, []byte(keyPass))
	pks := PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
	return pks
}

func GeneratePrivateKey() PrivateKey {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic("internal error")
	}

	pks := PrivateKey{
		key: ed25519.NewKeyFromSeed(key),
	}
	return pks
}

func (p *PrivateKey) Bytes() ed25519.PrivateKey {
	return p.key
}

func (p *PrivateKey) Sign(msg []byte) *Signture {
	value := ed25519.Sign(p.key, msg)
	signture := Signture{
		value: value,
	}
	return &signture
}

func (p *PrivateKey) Public() *PublicKey {
	pk := PublicKey{
		key: p.key.Public().(ed25519.PublicKey),
	}
	return &pk
}

type PublicKey struct {
	key ed25519.PublicKey
}

func (p *PublicKey) Bytes() ed25519.PublicKey {
	return p.key
}

type Address struct {
	value []byte
}

func (a Address) String() string {
	return hex.EncodeToString(a.value[:])
}
func (p Address) Bytes() ed25519.PublicKey {
	return p.value
}
func (p *PublicKey) Address() Address {
	return Address{value: p.key[:AddrLen]} //First 20 or AddrLen
}
