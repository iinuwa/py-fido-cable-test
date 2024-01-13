package noise

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
)

type noisePattern string

const (
	NoiseKNpsk0 noisePattern = "Noise_KNpsk0_P256_AESGCM_SHA256"
	NoiseNKpsk0 noisePattern = "Noise_NKpsk0_P256_AESGCM_SHA256"
)

const (
	protocolNameKNpsk0 string = "Noise_KNpsk0_P256_AESGCM_SHA256"
	protocolNameNKpsk0 string = "Noise_NKpsk0_P256_AESGCM_SHA256"
)

type CipherState struct {
	k [32]byte // key
	n uint32   // nonce
}

// CipherState InitializeKey(key)
func newCipherState(key []byte) CipherState {
	cs := CipherState{}
	cs.InitializeKey(key)
	return cs
}

func (cs *CipherState) InitializeKey(key []byte) {
	cs.k = [32]byte(key[:32])
	cs.n = 0
}

type SymmetricState struct {
	cs CipherState
	ck [noiseHashLen]byte
	h  [noiseHashLen]byte
	// h hash.Hash
}

func newSymmetricState(protocolName string) SymmetricState {
	ss := SymmetricState{}
	if len(protocolName) > noiseHashLen {
		h := noiseHash.New()
		ss.h = [noiseHashLen]byte(h.Sum([]byte(protocolName)))
	} else {
		zeros := [...]byte{
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
		}
		bytesWritten := copy(ss.h[:], protocolName)
		copy(ss.h[bytesWritten:noiseHashLen], zeros[:])
	}
	copy(ss.ck[:], ss.h[:])
	ss.cs = newCipherState(nil)
	return ss
}

func (ss *SymmetricState) MixKey(inputKeyMaterial []byte) {
	ck, tempK, _ := hkdf(ss.ck, inputKeyMaterial, 2)
	copy(ss.ck[:], ck[:])
	ss.cs.InitializeKey(tempK)
}

func (ss *SymmetricState) MixHash(data []byte) {
	h := noiseHash.New()
	h.Sum(ss.h[:])
	ss.h = [noiseHashLen]byte(h.Sum(data[:]))
}

func (ss *SymmetricState) MixKeyAndHash(inputKeyMaterial []byte) {
	ck, tempH, tempK := hkdf(ss.ck, inputKeyMaterial, 3)
	copy(ss.ck[:], ck[:])
	ss.MixHash(tempH)
	if noiseHashLen == 64 {
		tempK = tempK[:32]
	}
	ss.cs.InitializeKey(tempK)
}

type HandshakeState struct {
	ss              SymmetricState
	s               []byte // The local static key pair
	e               []byte // The local ephemeral key pair
	rs              []byte // The remote party’s static public key
	re              []byte // The remote party’s ephemeral public key
	initiator       bool
	messagePatterns [][]string
}

// HandshakeState Initialize()
func newHandshakeState(handshakePattern noisePattern, initiator bool, prologue []byte, s []byte, e []byte, rs []byte, re []byte) HandshakeState {
	hs := HandshakeState{
		initiator: initiator,
		s:         s,
		e:         e,
		rs:        rs,
		re:        re,
	}
	var protocolName string
	if handshakePattern == NoiseKNpsk0 {
		protocolName = protocolNameKNpsk0
	} else if handshakePattern == NoiseNKpsk0 {
		protocolName = protocolNameNKpsk0
	} else {
		panic("invalid handshake pattern given")
	}
	hs.ss = newSymmetricState(protocolName)
	hs.ss.MixHash(prologue)
	// repeat for initiator's public keys
	hs.ss.MixHash(rs)
	hs.ss.MixHash(re)
	// repeat for responder's public keys
	hs.ss.MixHash(publicKey)
}

type NoiseState struct {
	hs HandshakeState
}

func NewNoise(handshakePattern noisePattern, initiator bool, prologue []byte, s []byte, e []byte, rs []byte, re []byte) NoiseState {
	ns := NoiseState{}
	ns.hs = newHandshakeState(handshakePattern, initiator, prologue, s, e, rs, re)
	return ns
}

func (ns *NoiseState) MixKey(inputKeyMaterial []byte) {
	ns.hs.ss.MixKey(inputKeyMaterial)
}
func (ns *NoiseState) MixHash(data []byte) {
	ns.hs.ss.MixHash(data)
}

func MixHashPoint() {

}

func (ns *NoiseState) MixKeyAndHash(inputKeyMaterial []byte) {
	ns.hs.ss.MixKeyAndHash(inputKeyMaterial)
}

func hkdf(chainingKey [noiseHashLen]byte, inputKeyMaterial []byte, numOutputs int) ([]byte, []byte, []byte) {
	if numOutputs < 2 || numOutputs > 3 {
		panic("invalid number of outputs specified")
	}

	// Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
	tempKey := hmacHash(chainingKey[:], inputKeyMaterial)
	// Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
	output1 := hmacHash(tempKey[:noiseHashLen], []byte("\x01"))
	// Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
	output2 := hmacHash(tempKey[:noiseHashLen], []byte("\x02"))
	// If num_outputs == 2 then returns the pair (output1, output2).
	var output3 []byte = nil
	if numOutputs == 3 {
		// Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
		output3 = hmacHash(tempKey[:noiseHashLen], []byte("\x03"))
	}
	// Returns the triple (output1, output2, output3)
	return output1, output2, output3

}

func hmacHash(key []byte, data []byte) []byte {
	h := hmac.New(noiseHash.New, key[:])
	return h.Sum(data)
}

const (
	noiseHashLen = sha256.Size
	noiseHash    = crypto.SHA256
)
