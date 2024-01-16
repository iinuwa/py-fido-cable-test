package noise

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

type NoisePattern string

const (
	Noise_KNpsk0_P256_AESGCM_SHA256 NoisePattern = "Noise_KNpsk0_P256_AESGCM_SHA256"
	Noise_NKpsk0_P256_AESGCM_SHA256 NoisePattern = "Noise_NKpsk0_P256_AESGCM_SHA256"
)

const (
	protocolNameKNpsk0 string = "Noise_KNpsk0_P256_AESGCM_SHA256"
	protocolNameNKpsk0 string = "Noise_NKpsk0_P256_AESGCM_SHA256"
)

type CipherState struct {
	k [32]byte // key
	n uint64   // nonce
}

func newCipherState(key []byte) CipherState {
	cs := CipherState{}
	cs.initializeKey(key)
	return cs
}

func (cs *CipherState) initializeKey(key []byte) {
	cs.k = [32]byte(key[:32])
	cs.n = 0
}

func (cs *CipherState) encryptWithAd(ad []byte, plaintext []byte) []byte {
	if cs.k[:] == nil {
		return plaintext
	}

	n := cs.n
	ciphertext := encrypt(cs.k[:], n, ad, plaintext)
	cs.n++
	return ciphertext
}

func (cs *CipherState) decryptWithAd(ad []byte, ciphertext []byte) []byte {
	if cs.k[:] == nil {
		return ciphertext
	}

	n := cs.n
	plaintext := decrypt(cs.k[:], n, ad, ciphertext)
	cs.n++
	return plaintext
}

type symmetricState struct {
	cs CipherState
	ck [noiseHashLen]byte
	h  [noiseHashLen]byte
}

func newSymmetricState(protocolName string) symmetricState {
	ss := symmetricState{}
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

func (ss *symmetricState) mixKey(inputKeyMaterial []byte) {
	ck, tempK, _ := hkdf(ss.ck, inputKeyMaterial, 2)
	copy(ss.ck[:], ck[:])
	ss.cs.initializeKey(tempK)
}

func (ss *symmetricState) mixHash(data []byte) {
	h := noiseHash.New()
	h.Sum(ss.h[:])
	ss.h = [noiseHashLen]byte(h.Sum(data[:]))
}

func (ss *symmetricState) mixKeyAndHash(inputKeyMaterial []byte) {
	ck, tempH, tempK := hkdf(ss.ck, inputKeyMaterial, 3)
	copy(ss.ck[:], ck[:])
	ss.mixHash(tempH)
	if noiseHashLen == 64 {
		tempK = tempK[:32]
	}
	ss.cs.initializeKey(tempK)
}

func (ss *symmetricState) encryptAndHash(plaintext []byte) []byte {
	ciphertext := ss.cs.encryptWithAd(ss.h[:], plaintext)
	ss.mixHash(ciphertext)
	return ciphertext
}

func (ss *symmetricState) decryptAndHash(ciphertext []byte) []byte {
	plaintext := ss.cs.decryptWithAd(ss.h[:], ciphertext)
	ss.mixHash(ciphertext)
	return plaintext
}

func (ss *symmetricState) getHandshakeHash() [32]byte {
	return ss.h
}

func (ss *symmetricState) split() (*CipherState, *CipherState) {
	tempK1, tempK2, _ := hkdf(ss.ck, nil, 2)
	if noiseHashLen == 64 {
		tempK1 = tempK1[:32]
		tempK2 = tempK2[:32]
	}
	c1 := newCipherState(tempK1)
	c2 := newCipherState(tempK2)
	return &c1, &c2
}

type handshakeState struct {
	ss              symmetricState
	s               []byte // The local static key pair
	e               []byte // The local ephemeral key pair
	rs              []byte // The remote party’s static public key
	re              []byte // The remote party’s ephemeral public key
	initiator       bool
	messageTokens   []string
	patternPosition int
	psks            [][]byte
	pskPosition     int
}

// HandshakeState Initialize()
func initializeHandshakeState(handshakePattern NoisePattern, initiator bool, prologue []byte, s []byte, e []byte, rs []byte, re []byte, psks [][]byte) handshakeState {
	hs := handshakeState{
		initiator:       initiator,
		s:               s,
		e:               e,
		rs:              rs,
		re:              re,
		patternPosition: 0,
		psks:            psks,
		pskPosition:     0,
	}
	var protocolName string
	if handshakePattern == Noise_KNpsk0_P256_AESGCM_SHA256 {
		protocolName = protocolNameKNpsk0
		messageTokens := [10]string{"->", "s", "...", "->", "psk", "e", "<-", "e", "ee", "se"}
		hs.messageTokens = messageTokens[:]
	} else if handshakePattern == Noise_NKpsk0_P256_AESGCM_SHA256 {
		protocolName = protocolNameNKpsk0
		messageTokens := [10]string{"<-", "s", "...", "->", "psk", "e", "es", "<-", "e", "ee"}
		hs.messageTokens = messageTokens[:]
	} else {
		panic("invalid handshake pattern given")
	}
	hs.ss = newSymmetricState(protocolName)
	hs.ss.mixHash(prologue)
	// Mix in pre-message keys
	useRemoteKeys := !initiator
	for i, token := range hs.messageTokens {
		if token == "<-" {
			useRemoteKeys = !useRemoteKeys
		} else if token == "s" {
			if useRemoteKeys {
				hs.ss.mixHash(hs.rs)
			} else {
				staticKey, err := ecdh.P256().NewPrivateKey(hs.s)
				if err != nil {
					panic(err.Error())
				}
				hs.ss.mixHash(staticKey.PublicKey().Bytes())
			}
		} else if token == "..." {
			// finished with pre-messages
			hs.patternPosition = i + 1
			break
		}
	}
	return hs
}

func (hs *handshakeState) writeMessage(payload []byte, msgBuf []byte) {
	hasPsk := false
	for _, token := range hs.messageTokens {
		if token == "psk" {
			hasPsk = true
			break
		}
	}

	// skip message tokens for other side
	/*
		skippedTokens := 0
		for _, token := range hs.messageTokens[hs.patternPosition:] {
			if token == "->" {
				if hs.initiator {
					break
				} else {
					skippedTokens++
				}
			} else if token == "<-" {
				if hs.initiator {
					skippedTokens++
				} else {
					break
				}
			}
		}
		hs.patternPosition += skippedTokens + 1
	*/

	// process my tokens
	for i, token := range hs.messageTokens[hs.patternPosition:] {
		if token == "->" {
			if hs.initiator {
				continue

			} else {
				hs.patternPosition += i + 1
				break
			}
		} else if token == "<-" {
			if hs.initiator {
				hs.patternPosition += i + 1
				break
			} else {
				continue
			}
		} else if token == "e" {
			privKey, pubKey := generateKeypair()
			hs.e = privKey
			payload = append(payload, pubKey...)
			hs.ss.mixHash(hs.e)
			if hasPsk {
				hs.ss.mixKey(hs.e)
			}
		} else if token == "ee" {
			dhKey := dh(hs.e, hs.re)
			hs.ss.mixKey(dhKey)
		} else if token == "es" {
			var dhKey []byte
			if hs.initiator {
				dhKey = dh(hs.e, hs.rs)
			} else {
				dhKey = dh(hs.s, hs.re)
			}
			hs.ss.mixKey(dhKey)
		} else if token == "se" {
			var dhKey []byte
			if hs.initiator {
				dhKey = dh(hs.s, hs.re)
			} else {
				dhKey = dh(hs.e, hs.rs)
			}
			hs.ss.mixKey(dhKey)
		} else if token == "psk" {
			psk := hs.psks[hs.pskPosition]
			hs.ss.mixKeyAndHash(psk)
			hs.pskPosition++
		}
	}

	msgBuf = hs.ss.encryptAndHash(payload)
}
func (hs *handshakeState) readMessage(msg []byte, payloadBuf []byte) {
	hasPsk := false
	for _, token := range hs.messageTokens {
		if token == "psk" {
			hasPsk = true
			break
		}
	}

	// skip message tokens for other side
	skippedTokens := 0
	for _, token := range hs.messageTokens[hs.patternPosition:] {
		if token == "->" {
			if hs.initiator {
				break
			} else {
				skippedTokens++
			}
		} else if token == "<-" {
			if hs.initiator {
				skippedTokens++
			} else {
				break
			}
		}
	}
	hs.patternPosition += skippedTokens + 1

	for i, token := range hs.messageTokens[hs.patternPosition:] {
		if token == "->" {
			if hs.initiator {
				continue

			} else {
				hs.patternPosition += i + 1
				break
			}
		} else if token == "<-" {
			if hs.initiator {
				hs.patternPosition += i + 1
				break
			} else {
				continue
			}
		} else if token == "e" {
			hs.re = msg[:noiseDHLen]
			hs.ss.mixHash(hs.re)
			if hasPsk {
				hs.ss.mixKey(hs.re)
			}
		} else if token == "ee" {
			dhKey := dh(hs.e, hs.re)
			hs.ss.mixKey(dhKey)
		} else if token == "es" {
			var dhKey []byte
			if hs.initiator {
				dhKey = dh(hs.e, hs.rs)
			} else {
				dhKey = dh(hs.s, hs.re)
			}
			hs.ss.mixKey(dhKey)
		} else if token == "se" {
			var dhKey []byte
			if hs.initiator {
				dhKey = dh(hs.s, hs.re)
			} else {
				dhKey = dh(hs.e, hs.rs)
			}
			hs.ss.mixKey(dhKey)
		} else if token == "psk" {
			psk := hs.psks[hs.pskPosition]
			hs.ss.mixKeyAndHash(psk)
			hs.pskPosition++
		}
	}
	payloadBuf = hs.ss.decryptAndHash(msg[noiseDHLen:])
}

type NoiseState struct {
	hs handshakeState
}

func NewNoise(handshakePattern NoisePattern, initiator bool, prologue []byte, s []byte, e []byte, rs []byte, re []byte, psks [][]byte) *NoiseState {
	ns := NoiseState{}
	ns.hs = initializeHandshakeState(handshakePattern, initiator, prologue, s, e, rs, re, psks)
	return &ns
}

func (ns *NoiseState) MixKey(inputKeyMaterial []byte) {
	ns.hs.ss.mixKey(inputKeyMaterial)
}

func (ns *NoiseState) MixHash(data []byte) {
	ns.hs.ss.mixHash(data)
}

func (ns *NoiseState) MixKeyAndHash(inputKeyMaterial []byte) {
	ns.hs.ss.mixKeyAndHash(inputKeyMaterial)
}

func (ns *NoiseState) EncryptAndHash(plaintext []byte) []byte {
	return ns.hs.ss.encryptAndHash(plaintext)
}

func (ns *NoiseState) DecryptAndHash(ciphertext []byte) []byte {
	return ns.hs.ss.decryptAndHash(ciphertext)
}

func (ns *NoiseState) HandshakeHash() [32]byte {
	return ns.hs.ss.getHandshakeHash()
}

func (ns *NoiseState) WriteMessage(payload []byte) []byte {
	msgBuf := make([]byte, 0, 10)
	ns.hs.writeMessage(payload, msgBuf)
	return msgBuf
}

func (ns *NoiseState) ReadMessage(msg []byte) []byte {
	payloadBuf := make([]byte, 0, 10)
	ns.hs.readMessage(msg, payloadBuf)
	return payloadBuf
}

func (ns *NoiseState) Split() (*CipherState, *CipherState) {
	return ns.hs.ss.split()
}

func dh(privKey []byte, peerPubKey []byte) []byte {
	a, err := ecdh.P256().NewPrivateKey(privKey)
	if err != nil {
		panic(err.Error())
	}
	b, err := ecdh.P256().NewPublicKey(peerPubKey)
	if err != nil {
		panic(err.Error())
	}
	dhKey, err := a.ECDH(b)
	return dhKey
}
func encrypt(k []byte, n uint64, ad []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(k)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	var result []byte
	nonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonce, n)
	gcm.Seal(result, nonce, plaintext, ad)
	return result
}

func decrypt(k []byte, n uint64, ad []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(k)
	if err != nil {
		panic(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	var result []byte
	nonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonce, n)
	_, err = gcm.Open(result, nonce, ciphertext, ad)
	if err != nil {
		panic(err.Error())
	}
	return result
}

func generateKeypair() (privKey []byte, pubKey []byte) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err.Error())
	}
	return key.Bytes(), key.PublicKey().Bytes()
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
	noiseDHLen   = 1 + 32 + 32 // X9.62 ECDH public key
)
