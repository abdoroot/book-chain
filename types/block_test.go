package types

import (
	cr "crypto/rand"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/abdoroot/book-chain/crypto"
	"github.com/stretchr/testify/assert"
)

func TestHashBlock(t *testing.T) {
	block := RandomBlock()
	hash := HashBlock(&block)
	//fmt.Println(hash,hex.EncodeToString(hash))
	assert.Equal(t, 32, len(hash))
}

func TestSignBlock(t *testing.T) {
	b := RandomBlock()
	prvKey := crypto.GeneratePrivateKey()
	pubKey := prvKey.Public()
	sig := SignBlock(prvKey, &b)
	assert.Equal(t, 64, len(sig.Bytes()))
	assert.True(t, sig.Verfiy(pubKey, HashBlock(&b)))
}

func RandomHash() []byte {
	hash := make([]byte, 32)
	io.ReadFull(cr.Reader, hash)
	return hash
}

func RandomBlock() Block {
	header := Header{
		Version:   1,
		Heights:   int32(rand.Intn(1000)),
		PrevHash:  RandomHash(),
		RootHash:  RandomHash(),
		Timestamp: time.Now().Unix(),
	}

	return Block{
		Header: &header,
	}
}
