package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateKeys(t *testing.T) {
	pr := GeneratePrivateKey()
	assert.Equal(t, len(pr.Bytes()), 64)

	PublicKey := pr.Public()
	assert.Equal(t, len(PublicKey.Bytes()), 32)
}

func TestPrivateKeySign(t *testing.T) {
	pr := GeneratePrivateKey()
	msg := []byte("foo bar bax")
	signture := pr.Sign(msg)

	assert.Equal(t, len(signture.Bytes()), 64)
	//test with valid key and message
	assert.True(t, signture.Verfiy(pr.Public(), msg))
	//test with invalid message
	assert.False(t, signture.Verfiy(pr.Public(), []byte("New Message")))
	//test with invalid private key
	ipr := GeneratePrivateKey()
	assert.False(t, signture.Verfiy(ipr.Public(), msg))
}

func TestPublicKeyAddress(t *testing.T) {
	pr := GeneratePrivateKey()
	puk := pr.Public()
	addr := puk.Address()
	fmt.Println("address:", addr.String())
}

func TestNewPrivateKeyFromString(t *testing.T) {
	keyPass := "AbdelhadiMohamed200930" //Save this to rettreive the private key
	pr := NewPrivateKeyFromString(keyPass)
	assert.Equal(t, len(pr.Bytes()), 64)

	PublicKey := pr.Public()
	assert.Equal(t, len(PublicKey.Bytes()), 32)

	addr := PublicKey.Address()
	fmt.Println(addr.String())
}
