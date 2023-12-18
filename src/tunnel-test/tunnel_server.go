package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const WEBSOCKET_HANDSHAKE_GUID string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type slice struct {
	Data   []byte
	Length int
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		c := http.NewResponseController(w)
		err := c.EnableFullDuplex()
		if err != nil {
			return
		}
		if !hasHeaderValue(r.Header, "Connection", "Upgrade") {
			w.WriteHeader(400)
			w.Write([]byte("not an upgrade request"))
			return
		} else if !hasHeaderValue(r.Header, "Upgrade", "websocket") {
			w.WriteHeader(400)
			w.Write([]byte("not a websocket"))
			return
		}

		ws_proto_version := r.Header.Get("Sec-WebSocket-Version")
		if ws_proto_version != "13" {
			w.WriteHeader(400)
			if ws_proto_version != "" {
				w.Write([]byte(fmt.Sprintf("WebSocket protocol version %s not understood", ws_proto_version)))
			} else {
				w.Write([]byte("WebSocket protocol version not specified"))
			}
			return
		}

		// ws_protocols := strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",")

		ws_key := r.Header.Get("Sec-WebSocket-Key")
		if ws_key == "" {
			w.WriteHeader(400)
			w.Write([]byte("websocket key missing"))
			return
		}
		w.Header().Add("Upgrade", "websocket")

		output := sha1.Sum([]byte(ws_key + WEBSOCKET_HANDSHAKE_GUID))
		accept_str := base64.StdEncoding.EncodeToString(output[:])
		w.Header().Add("Sec-WebSocket-Accept", accept_str)

		var client_buf bytes.Buffer
		_, err = client_buf.ReadFrom(r.Body)
		if err != nil {
			return
		}

		w.WriteHeader(101)

		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buf.Flush()
		println("starting read loop")
		ch := make(chan slice)
		go processWebSocketConnection(ch, buf)
		missed := 0
	loop:
		for {
			if missed > 100 {
				break loop
			}
			select {
			case b, ok := <-ch:
				missed = 0
				if !ok {
					close(ch)
					break loop
				} else {
					data, err := processFrame(b.Data[:b.Length])
					if err != nil {
						close(ch)
						break loop
					}
					println(string(data))
				}
			case <-time.After(100 * time.Millisecond):
				missed++
			}
		}
	})
	println("Starting WebSocket server")
	http.ListenAndServe(":8080", nil)
}

func processWebSocketConnection(ch chan slice, buf *bufio.ReadWriter) {
	for {
		var b [255]byte
		println("processing ws connection...")
		bytes_read, err := buf.Read(b[:])
		if err == io.EOF {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err != nil {
			close(ch)
			ch <- slice{nil, 1}
			return
		}
		ch <- slice{b[:], bytes_read}
	}
}

func processFrame(data []byte) (r []byte, err error) {
	// fin := data[0] >> 7
	if data[0]&0b01110000 != 0 {
		r = nil
		err = fmt.Errorf("reserved fields are not zero")
		return
	}
	/*
		opcode := data[0] & 0b00001111
		var op string
		switch opcode {
		case 0x00:
			op := "continue"
		case 0x01:
			op := "text"
		case 0x02:
			op := "binary"
		case 0x08:
			op := "close"
		case 0x09:
			op := "ping"
		case 0x0A:
			op := "pong"
		}
	*/
	masked := data[1]&0b10000000 > 0
	payload_len := uint64(data[1] & 0b01111111)
	v_start := 2
	if payload_len == 126 {
		payload_len = uint64(binary.BigEndian.Uint16(data[2:4]))
		v_start = 4
	} else if payload_len == 127 {
		payload_len = binary.BigEndian.Uint64(data[2:10])
		v_start = 10
	} else if payload_len > 127 {
		r = nil
		err = fmt.Errorf("invalid payload length field")
		return
	}
	var payload_data []byte
	if masked {
		masking_key := data[v_start : v_start+4]
		payload_data = data[v_start+4 : uint64(v_start+4)+payload_len]
		for i := 0; uint64(i) < payload_len; i++ {
			payload_data[i] ^= masking_key[i%4]
		}
	} else {
		payload_data = data[v_start : uint64(v_start)+payload_len]
	}
	r = payload_data
	err = nil
	return
}

func hasHeaderValue(headers http.Header, name string, expectedValue string) bool {
	l := strings.Split(headers.Get(name), ",")
	for i := 0; i < len(l); i++ {
		if strings.EqualFold(l[i], expectedValue) {
			return true
		}
	}
	return false
}
