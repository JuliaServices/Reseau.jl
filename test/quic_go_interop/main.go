// Command quic_go_interop runs quic-go as the peer of a Reseau QUIC
// connection over UDP, for test/quic_go_interop_tests.jl.
//
//	quic_go_interop server -cert FILE -key FILE -addr HOST:0
//
// prints "ADDR host:port" once listening, then serves until stdin closes. It
// echoes every bidirectional stream back on the same stream, and answers
// every unidirectional stream with one of its own carrying the same bytes.
//
//	quic_go_interop client -addr HOST:PORT -size N -streams K
//
// sends N random bytes on each of K bidirectional streams and on one
// unidirectional stream, checks that the server returns them the way the
// server above does, closes the connection with application error 0, and
// prints "OK".
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const alpn = "reseau-interop"

func quicConfig() *quic.Config {
	return &quic.Config{MaxIdleTimeout: 20 * time.Second}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: quic_go_interop server|client ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = server(os.Args[2:])
	case "client":
		err = client(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "quic_go_interop:", err)
		os.Exit(1)
	}
}

func server(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	certFile := fs.String("cert", "", "certificate file")
	keyFile := fs.String("key", "", "key file")
	addr := fs.String("addr", "127.0.0.1:0", "address to listen on")
	fs.Parse(args)
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}
	ln, err := quic.ListenAddr(*addr, tlsConf, quicConfig())
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("ADDR %s\n", ln.Addr().(*net.UDPAddr).AddrPort())
	go func() {
		// The test closes stdin to stop the server.
		io.Copy(io.Discard, os.Stdin)
		ln.Close()
	}()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return nil
		}
		go serveConn(conn)
	}
}

func serveConn(conn quic.Connection) {
	ctx := conn.Context()
	go func() {
		for {
			str, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go func() {
				data, err := io.ReadAll(str)
				if err != nil {
					fmt.Fprintln(os.Stderr, "uni stream read:", err)
					return
				}
				out, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					fmt.Fprintln(os.Stderr, "open uni stream:", err)
					return
				}
				out.Write(data)
				out.Close()
			}()
		}
	}()
	for {
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			if _, err := io.Copy(str, str); err != nil {
				fmt.Fprintln(os.Stderr, "echo:", err)
			}
			str.Close()
		}()
	}
}

func client(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	addr := fs.String("addr", "", "server address")
	size := fs.Int("size", 1<<20, "bytes per stream")
	streams := fs.Int("streams", 4, "bidirectional streams")
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}, ServerName: "localhost"}
	conn, err := quic.DialAddr(ctx, *addr, tlsConf, quicConfig())
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	errs := make(chan error, *streams+1)
	var wg sync.WaitGroup
	for i := 0; i < *streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- echoStream(ctx, conn, *size)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		errs <- uniRoundTrip(ctx, conn, *size)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			conn.CloseWithError(1, err.Error())
			return err
		}
	}
	conn.CloseWithError(0, "done")
	fmt.Println("OK")
	return nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func echoStream(ctx context.Context, conn quic.Connection, size int) error {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	data := randomBytes(size)
	writeErr := make(chan error, 1)
	go func() {
		_, err := str.Write(data)
		if err == nil {
			err = str.Close()
		}
		writeErr <- err
	}()
	got, err := io.ReadAll(bufio.NewReader(str))
	if err != nil {
		return fmt.Errorf("stream %d read: %w", str.StreamID(), err)
	}
	if err := <-writeErr; err != nil {
		return fmt.Errorf("stream %d write: %w", str.StreamID(), err)
	}
	if !bytes.Equal(got, data) {
		return fmt.Errorf("stream %d: echoed %d bytes differ from the %d sent", str.StreamID(), len(got), len(data))
	}
	return nil
}

func uniRoundTrip(ctx context.Context, conn quic.Connection, size int) error {
	out, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open uni stream: %w", err)
	}
	data := randomBytes(size)
	if _, err := out.Write(data); err != nil {
		return fmt.Errorf("uni write: %w", err)
	}
	out.Close()
	in, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return fmt.Errorf("accept uni stream: %w", err)
	}
	got, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("uni read: %w", err)
	}
	if !bytes.Equal(got, data) {
		return errors.New("unidirectional reply differs from what was sent")
	}
	return nil
}
