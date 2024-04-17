package types

import (
	"crypto/sha256"
	"log"

	"github.com/abdoroot/book-chain/crypto"
	"google.golang.org/protobuf/proto"
)

func HashBlock(block *Block) []byte {
	b, err := proto.Marshal(block)
	if err != nil {
		log.Println("error marshaling block data")
		panic(err)
	}
	hashSum := sha256.Sum256(b)
	return hashSum[:]
}

func SignBlock(pk crypto.PrivateKey, block *Block) *crypto.Signture {
	hash := HashBlock(block)
	return pk.Sign(hash)
}
