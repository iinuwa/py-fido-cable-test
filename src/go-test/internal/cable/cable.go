package cable

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/hkdf"
	"iinuwa.xyz/cable-test/internal/cable/noise"
)

func main() {
	qr_secret, err := os.ReadFile("data/qr_secret.key")
	if err != nil {
		panic("BOGUS!")
	}
	var eid_key [32 + 32]byte
	Derive(eid_key[:], qr_secret, nil, KeyPurposeEIDKey)
	candidateAdvert, err := os.ReadFile("data/advert.bin")
	if err != nil {
		panic("BOGUS!")
	}
	plaintext, success := trialDecrypt(&eid_key, candidateAdvert)
	if !success {
		panic("BOGUS!")
	}
	_, _, _ = unpackDecryptedAdvert(plaintext)
	domain, _ := decodeTunnelServerDomain(256)
	println(domain)

}

func digitEncode(d []byte) string {
	const chunkSize = 7
	const chunkDigits = 17
	const zeros = "00000000000000000"

	var ret string
	for len(d) >= chunkSize {
		var chunk [8]byte
		copy(chunk[:], d[:chunkSize])
		v := strconv.FormatUint(binary.LittleEndian.Uint64(chunk[:]), 10)
		ret += zeros[:chunkDigits-len(v)]
		ret += v

		d = d[chunkSize:]
	}

	if len(d) != 0 {
		// partialChunkDigits is the number of digits needed to encode
		// each length of trailing data from 6 bytes down to zero. I.e.
		// it’s 15, 13, 10, 8, 5, 3, 0 written in hex.
		const partialChunkDigits = 0x0fda8530

		digits := 15 & (partialChunkDigits >> (4 * len(d)))
		var chunk [8]byte
		copy(chunk[:], d)
		v := strconv.FormatUint(binary.LittleEndian.Uint64(chunk[:]), 10)
		ret += zeros[:digits-len(v)]
		ret += v
	}

	return ret
}

func encodeQRContents(compressedPublicKey *[33]byte, qrSecret *[16]byte) string {
	numMapElements := 6
	lenAssignedTunnelServerDomains := 2
	cborMajorByteString := byte(0b010_00000)
	var cbor []byte
	cbor = append(cbor, 0xa0+byte(numMapElements))       // CBOR map
	cbor = append(cbor, 0)                               // key 0
	cbor = append(cbor, (cborMajorByteString<<5)|24, 33) // 33 bytes
	cbor = append(cbor, compressedPublicKey[:]...)
	cbor = append(cbor, 1)                           // key 1
	cbor = append(cbor, (cborMajorByteString<<5)|16) // 16 bytes
	cbor = append(cbor, qrSecret[:]...)

	cbor = append(cbor, 2) // key 2
	n := lenAssignedTunnelServerDomains
	if n > 24 {
		panic("larger encoding needed")
	}
	cbor = append(cbor, byte(n))

	cbor = append(cbor, 3) // key 3
	cbor = append(cbor, cborEncodeInt64(time.Now().Unix())...)

	cbor = append(cbor, 4)    // key 4
	cbor = append(cbor, 0xf5) // true

	cbor = append(cbor, 5) // key 5
	cbor = append(cbor, (cborMajorByteString<<5)|2, 'm', 'c')

	// if extraKey {
	// 	cbor = append(cbor, 0x19, 0xff, 0xff, 0) // key 65535, value 0
	// }

	qr := "FIDO:/" + digitEncode(cbor)
	fmt.Println(qr)
	return qr
}

func cborEncodeInt64(num int64) []byte {
	// assuming positive
	var b []byte
	if num >= 0 && num < 24 {
		b = append(b, byte(num))
	} else if num >= 24 && num < 256 {
		b = append(b, 0b000_11000, byte(num))
	} else if num >= 256 && num < 2^16 {
		b = append(b, 0b000_11001)
		binary.BigEndian.AppendUint16(b, uint16(num))
	} else if num >= 2^16 && num < 2^32 {
		b = append(b, 0b000_11010)
		binary.BigEndian.AppendUint32(b, uint32(num))
	} else if num >= 2^32 && num < 2^64 {
		b = append(b, 0b000_11011)
		binary.BigEndian.AppendUint64(b, uint64(num))
	}
	return b
}

func trialDecrypt(eidKey *[64]byte, candidateAdvert []byte) (plaintext [16]byte, ok bool) {
	var zeros [16]byte
	if len(candidateAdvert) != 20 {
		return zeros, false
	}

	h := hmac.New(sha256.New, eidKey[32:])
	h.Write(candidateAdvert[:16])
	expectedTag := h.Sum(nil)
	tag := candidateAdvert[16:]
	if !hmac.Equal(expectedTag[:4], tag) {
		return zeros, false
	}

	block, err := aes.NewCipher(eidKey[:32])
	if err != nil {
		panic(err)
	}

	block.Decrypt(plaintext[:], candidateAdvert[:16])
	if !reservedBitsAreZero(plaintext) {
		return zeros, false
	}

	return plaintext, true
}

func reservedBitsAreZero(plaintext [16]byte) bool {
	return plaintext[0] == 0
}

type keyPurpose uint32

const (
	KeyPurposeEIDKey   keyPurpose = 1
	KeyPurposeTunnelID keyPurpose = 2
	KeyPurposePSK      keyPurpose = 3
)

func Derive(output, secret, salt []byte, purpose keyPurpose) {
	if uint32(purpose) >= 0x100 {
		panic("unsupported purpose")
	}

	var purpose32 [4]byte
	purpose32[0] = byte(purpose)

	h := hkdf.New(sha256.New, secret, salt, purpose32[:])
	if n, err := h.Read(output); err != nil || n != len(output) {
		panic("HKDF error")
	}
}

func unpackDecryptedAdvert(plaintext [16]byte) (
	nonce [10]byte,
	routingID [3]byte,
	encodedTunnelServerDomain uint16) {

	copy(nonce[:], plaintext[1:])
	copy(routingID[:], plaintext[11:])
	encodedTunnelServerDomain = uint16(plaintext[14]) | (uint16(plaintext[15]) << 8)
	return
}

var assignedTunnelServerDomains = []string{"cable.ua5v.com", "cable.auth.com"}

func decodeTunnelServerDomain(encoded uint16) (string, bool) {
	if encoded < 256 {
		if int(encoded) >= len(assignedTunnelServerDomains) {
			return "", false
		}
		return assignedTunnelServerDomains[encoded], true
	}

	shaInput := []byte{
		0x63, 0x61, 0x42, 0x4c, 0x45, 0x76, 0x32, 0x20,
		0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x20, 0x73,
		0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x64, 0x6f,
		0x6d, 0x61, 0x69, 0x6e,
	}
	shaInput = append(shaInput, byte(encoded), byte(encoded>>8), 0)
	println(hex.EncodeToString(shaInput))
	digest := sha256.Sum256(shaInput)

	v := binary.LittleEndian.Uint64(digest[:8])
	tldIndex := uint(v & 3)
	v >>= 2

	ret := "cable."
	const base32Chars = "abcdefghijklmnopqrstuvwxyz234567"
	for v != 0 {
		ret += string(base32Chars[v&31])
		v >>= 5
	}

	tlds := []string{".com", ".org", ".net", ".info"}
	ret += tlds[tldIndex&3]

	return ret, true
}

const P256X962Length = 1 + 32 + 32

func InitialHandshakeMessage(
	psk [32]byte,
	priv *ecdsa.PrivateKey,
	peerPub *ecdsa.PublicKey) (

	msg []byte,
	ephemeralKey *ecdsa.PrivateKey,
	noise *noise.NoiseState) {

	if (priv == nil) == (peerPub == nil) {
		panic("exactly one of priv and peerPub must be given")
	}

	var ns *noise.NoiseState
	if peerPub != nil {
		ns = noise.NewNoise(noise.NoiseNKpsk0)
		ns.MixHash([]byte{0})
		ns.MixHashPoint(peerPub)
	} else {
		ns = noise.NewNoise(noise.NoiseKNpsk0)
		ns.MixHash([]byte{1})
		ns.MixHashPoint(&priv.PublicKey)
	}

	ns.MixKeyAndHash(psk[:])

	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	ephemeralKeyBytes := elliptic.Marshal(ephemeralKey.Curve, ephemeralKey.X, ephemeralKey.Y)
	ns.mixHash(ephemeralKeyBytes)
	ns.mixKey(ephemeralKeyBytes)

	if peerPub != nil {
		ns.mixKey(ecdh(ephemeralKey, peerPub.X, peerPub.Y))
	}

	msg = append(msg, ephemeralKeyBytes...)
	msg = append(msg, ns.encryptAndHash(nil)...)

	return msg, ephemeralKey, ns
}

func processHandshakeResponse(
	peerHandshakeMessage []byte,
	ephemeralKey *ecdsa.PrivateKey,
	priv *ecdsa.PrivateKey,
	ns *noiseState) (

	keys trafficKeys,
	handshakeHash [32]byte) {

	if len(peerHandshakeMessage) < p256X962Length {
		panic("handshake too short")
	}

	peerPointBytes := peerHandshakeMessage[:p256X962Length]
	ciphertext := peerHandshakeMessage[p256X962Length:]

	ns.mixHash(peerPointBytes)
	ns.mixKey(peerPointBytes)

	peerPointX, peerPointY := elliptic.Unmarshal(ephemeralKey.Curve, peerPointBytes)
	if peerPointX == nil {
		panic("peer’s point is not on the curve")
	}

	ns.mixKey(ecdh(ephemeralKey, peerPointX, peerPointY))

	if priv != nil {
		ns.mixKey(ecdh(priv, peerPointX, peerPointY))
	}

	plaintext, ok := ns.decryptAndHash(ciphertext)
	if !ok || len(plaintext) != 0 {
		panic("bad handshake")
	}

	return ns.split(), ns.handshakeHash()
}
