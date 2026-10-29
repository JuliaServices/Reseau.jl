// Command quic_interop runs Go's crypto/tls QUICConn as the peer of a Reseau
// QUICConn for test/tls_quic_go_interop_tests.jl.
//
// The two sides take turns over stdin/stdout. Every frame is
//
//	type (1 byte) | level (1 byte) | payload length (4 bytes, big endian) | payload
//
// On its turn the helper reports its QUIC events and ends with an 'I' frame.
// It then reads the test's frames until the test's own 'I'.
//
// Helper to test:
//
//	'D' CRYPTO data to deliver at level
//	'R' read secret at level: suite (2 bytes) | secret
//	'W' write secret at level: suite (2 bytes) | secret
//	'P' the transport parameters the helper received
//	'H' handshake done: did resume (1 byte) | negotiated ALPN
//	'E' handshake failed: alert (1 byte) | message
//	'I' end of turn
//
// Test to helper:
//
//	'D' CRYPTO data received from the Reseau side at level
//	'I' end of turn
//	'N' close this connection and start the next one
//	'Q' exit
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type frame struct {
	kind    byte
	level   byte
	payload []byte
}

func readFrame(r io.Reader) (frame, error) {
	var header [6]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return frame{}, err
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[2:]))
	if _, err := io.ReadFull(r, payload); err != nil {
		return frame{}, err
	}
	return frame{header[0], header[1], payload}, nil
}

func writeFrame(w *bufio.Writer, kind, level byte, payload []byte) {
	var header [6]byte
	header[0] = kind
	header[1] = level
	binary.BigEndian.PutUint32(header[2:], uint32(len(payload)))
	w.Write(header[:])
	w.Write(payload)
}

func secretPayload(suite uint16, secret []byte) []byte {
	out := make([]byte, 2, 2+len(secret))
	binary.BigEndian.PutUint16(out, suite)
	return append(out, secret...)
}

func errorPayload(err error) []byte {
	alert := byte(80) // internal_error
	var ae tls.AlertError
	if errors.As(err, &ae) {
		alert = byte(ae)
	}
	return append([]byte{alert}, err.Error()...)
}

func parseCurves(spec string) ([]tls.CurveID, error) {
	if spec == "" {
		return nil, nil
	}
	var curves []tls.CurveID
	for _, name := range strings.Split(spec, ",") {
		switch name {
		case "X25519":
			curves = append(curves, tls.X25519)
		case "P256":
			curves = append(curves, tls.CurveP256)
		case "P384":
			curves = append(curves, tls.CurveP384)
		default:
			return nil, fmt.Errorf("unknown curve %q", name)
		}
	}
	return curves, nil
}

func main() {
	role := flag.String("role", "client", "client or server")
	certFile := flag.String("cert", "", "server certificate (PEM)")
	keyFile := flag.String("key", "", "server private key (PEM)")
	caFile := flag.String("ca", "", "CA used by the client to verify the server")
	serverName := flag.String("server-name", "localhost", "client SNI and verification name")
	alpn := flag.String("alpn", "h3", "comma-separated ALPN protocols")
	curves := flag.String("curves", "", "comma-separated curve preferences")
	params := flag.String("params", "", "transport parameters to send")
	flag.Parse()

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: strings.Split(*alpn, ","),
	}
	curvePrefs, err := parseCurves(*curves)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	config.CurvePreferences = curvePrefs
	isServer := *role == "server"
	if isServer {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		config.Certificates = []tls.Certificate{cert}
	} else {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "no certificates in", *caFile)
			os.Exit(2)
		}
		config.RootCAs = roots
		config.ServerName = *serverName
		config.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	}

	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	for {
		if !runConnection(config, isServer, []byte(*params), in, out) {
			return
		}
	}
}

// runConnection runs one handshake and returns whether the test asked for
// another connection.
func runConnection(config *tls.Config, isServer bool, params []byte, in *bufio.Reader, out *bufio.Writer) bool {
	qc := &tls.QUICConfig{TLSConfig: config}
	var conn *tls.QUICConn
	if isServer {
		conn = tls.QUICServer(qc)
	} else {
		conn = tls.QUICClient(qc)
	}
	defer conn.Close()
	conn.SetTransportParameters(params)
	failure := conn.Start(context.Background())
	reported := false
	for {
		for failure == nil {
			e := conn.NextEvent()
			if e.Kind == tls.QUICNoEvent {
				break
			}
			switch e.Kind {
			case tls.QUICSetReadSecret:
				writeFrame(out, 'R', byte(e.Level), secretPayload(e.Suite, e.Data))
			case tls.QUICSetWriteSecret:
				writeFrame(out, 'W', byte(e.Level), secretPayload(e.Suite, e.Data))
			case tls.QUICWriteData:
				writeFrame(out, 'D', byte(e.Level), e.Data)
			case tls.QUICTransportParameters:
				writeFrame(out, 'P', 0, e.Data)
			case tls.QUICHandshakeDone:
				state := conn.ConnectionState()
				resumed := byte(0)
				if state.DidResume {
					resumed = 1
				}
				writeFrame(out, 'H', 0, append([]byte{resumed}, state.NegotiatedProtocol...))
				if isServer {
					failure = conn.SendSessionTicket(tls.QUICSessionTicketOptions{})
				}
			}
		}
		if failure != nil && !reported {
			writeFrame(out, 'E', 0, errorPayload(failure))
			reported = true
		}
		writeFrame(out, 'I', 0, nil)
		if err := out.Flush(); err != nil {
			os.Exit(1)
		}
	read:
		for {
			f, err := readFrame(in)
			if err != nil {
				os.Exit(0)
			}
			switch f.kind {
			case 'D':
				if failure == nil {
					failure = conn.HandleData(tls.QUICEncryptionLevel(f.level), f.payload)
				}
			case 'I':
				break read
			case 'N':
				return true
			case 'Q':
				return false
			}
		}
	}
}
