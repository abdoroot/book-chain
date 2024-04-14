package crypto

import (
	"crypto/ed25519"
)

type Signture struct {
	value []byte
}

func (s *Signture) Bytes() ed25519.PublicKey {
	return s.value
}

func (s *Signture) Verfiy(pubkey *PublicKey, msg []byte) bool {
	return ed25519.Verify(pubkey.Bytes(), msg, s.Bytes())
}
