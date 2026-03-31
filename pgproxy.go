// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The pgproxy server is a proxy for the Postgres wire protocol.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"expvar"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	pgproto3 "github.com/jackc/pgproto3/v2"
	"tailscale.com/client/local"
	"tailscale.com/metrics"
	"tailscale.com/tsnet"
	"tailscale.com/tsweb"
)

var (
	hostname     = flag.String("hostname", "", "Tailscale hostname to serve on")
	port         = flag.Int("port", 5432, "Listening port for client connections")
	debugPort    = flag.Int("debug-port", 80, "Listening port for debug/metrics endpoint")
	upstreamAddr = flag.String("upstream-addr", "", "Address of the upstream Postgres server, in host:port format")
	upstreamCA   = flag.String("upstream-ca-file", "", "File containing the PEM-encoded CA certificate for the upstream server")
	tailscaleDir = flag.String("state-dir", "", "Directory in which to store the Tailscale auth state")
)

func main() {
	flag.Parse()
	if *hostname == "" {
		log.Fatal("missing --hostname")
	}
	if *upstreamAddr == "" {
		log.Fatal("missing --upstream-addr")
	}
	if *upstreamCA == "" {
		log.Fatal("missing --upstream-ca-file")
	}
	if *tailscaleDir == "" {
		log.Fatal("missing --state-dir")
	}

	ts := &tsnet.Server{
		Dir:      *tailscaleDir,
		Hostname: *hostname,
	}

	if os.Getenv("TS_AUTHKEY") == "" {
		log.Print("Note: you need to run this with TS_AUTHKEY=... the first time, to join your tailnet of choice.")
	}

	tsclient, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("getting tsnet API client: %v", err)
	}

	p, err := newProxy(*upstreamAddr, *upstreamCA, tsclient)
	if err != nil {
		log.Fatal(err)
	}
	expvar.Publish("pgproxy", p.Expvar())

	if *debugPort != 0 {
		mux := http.NewServeMux()
		tsweb.Debugger(mux)
		srv := &http.Server{
			Handler: mux,
		}
		dln, err := ts.Listen("tcp", fmt.Sprintf(":%d", *debugPort))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			log.Fatal(srv.Serve(dln))
		}()
	}

	ln, err := ts.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving access to %s on port %d", *upstreamAddr, *port)
	log.Fatal(p.Serve(ln))
}

// proxy is a postgres wire protocol proxy, which strictly enforces
// the security of the TLS connection to its upstream regardless of
// what the client's TLS configuration is.
type proxy struct {
	upstreamAddr     string // "my.database.com:5432"
	upstreamHost     string // "my.database.com"
	upstreamCertPool *x509.CertPool
	downstreamCert   []tls.Certificate
	client           *local.Client

	activeSessions  expvar.Int
	startedSessions expvar.Int
	errors          metrics.LabelMap
}

// newProxy returns a proxy that forwards connections to
// upstreamAddr. The upstream's TLS session is verified using the CA
// cert(s) in upstreamCAPath.
func newProxy(upstreamAddr, upstreamCAPath string, client *local.Client) (*proxy, error) {
	bs, err := os.ReadFile(upstreamCAPath)
	if err != nil {
		return nil, err
	}
	upstreamCertPool := x509.NewCertPool()
	if !upstreamCertPool.AppendCertsFromPEM(bs) {
		return nil, fmt.Errorf("invalid CA cert in %q", upstreamCAPath)
	}

	h, _, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		return nil, err
	}
	downstreamCert, err := mkSelfSigned(h)
	if err != nil {
		return nil, err
	}

	return &proxy{
		upstreamAddr:     upstreamAddr,
		upstreamHost:     h,
		upstreamCertPool: upstreamCertPool,
		downstreamCert:   []tls.Certificate{downstreamCert},
		client:           client,
		errors:           metrics.LabelMap{Label: "kind"},
	}, nil
}

// Expvar returns p's monitoring metrics.
func (p *proxy) Expvar() expvar.Var {
	ret := &metrics.Set{}
	ret.Set("sessions_active", &p.activeSessions)
	ret.Set("sessions_started", &p.startedSessions)
	ret.Set("session_errors", &p.errors)
	return ret
}

// Serve accepts postgres client connections on ln and proxies them to
// the configured upstream. ln can be any net.Listener, but all client
// connections must originate from tailscale IPs that can be verified
// with WhoIs.
func (p *proxy) Serve(ln net.Listener) error {
	var lastSessionID int64
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		id := time.Now().UnixNano()
		if id == lastSessionID {
			// Bluntly enforce SID uniqueness, even if collisions are
			// fantastically unlikely (but OSes vary in how much timer
			// precision they expose to the OS, so id might be rounded
			// e.g. to the same millisecond)
			id++
		}
		lastSessionID = id
		go func(sessionID int64) {
			if err := p.serve(sessionID, c); err != nil {
				log.Printf("%d: session ended with error: %v", sessionID, err)
			}
		}(id)
	}
}

var (
	// sslStart is the magic bytes that postgres clients use to indicate
	// that they want to do a TLS handshake. Servers should respond with
	// the single byte "S" before starting a normal TLS handshake.
	sslStart = [8]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	// plaintextStart is the magic bytes that postgres clients use to
	// indicate that they're starting a plaintext authentication
	// handshake.
	plaintextStart = [8]byte{0, 0, 0, 86, 0, 3, 0, 0}
)

// serve proxies the postgres client on c to the proxy's upstream,
// enforcing strict TLS to the upstream.
func (p *proxy) serve(sessionID int64, clientConn net.Conn) error {
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	whois, err := p.client.WhoIs(ctx, clientConn.RemoteAddr().String())
	if err != nil {
		p.errors.Add("whois-failed", 1)
		return fmt.Errorf("getting client identity: %v", err)
	}

	// Before anything else, log the connection attempt.
	tailscaleUser, machine := "", ""
	if whois.Node != nil {
		if whois.Node.Hostinfo.ShareeNode() {
			machine = "external-device"
		} else {
			machine = strings.TrimSuffix(whois.Node.Name, ".")
		}
	}
	if whois.UserProfile != nil {
		tailscaleUser = whois.UserProfile.LoginName
		if tailscaleUser == "tagged-devices" && whois.Node != nil {
			tailscaleUser = strings.Join(whois.Node.Tags, ",")
		}
	}
	if tailscaleUser == "" || machine == "" {
		p.errors.Add("no-ts-identity", 1)
		return fmt.Errorf("couldn't identify source user and machine (user %q, machine %q)", tailscaleUser, machine)
	}
	log.Printf("%d: session start, from %s (machine %s, user %s)", sessionID, clientConn.RemoteAddr(), machine, tailscaleUser)
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf("%d: session end, from %s (machine %s, user %s), lasted %s", sessionID, clientConn.RemoteAddr(), machine, tailscaleUser, elapsed.Round(time.Millisecond))
	}()

	// Read the client's opening message, to figure out if it's trying
	// to TLS or not.
	var buf [8]byte
	if _, err := io.ReadFull(clientConn, buf[:len(sslStart)]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("initial magic read: %v", err)
	}
	var clientIsTLS bool
	switch {
	case buf == sslStart:
		clientIsTLS = true
		log.Print("TLS is enabled")
	case buf == plaintextStart:
		clientIsTLS = false
		log.Print("TLS is disabled")
	default:
		p.errors.Add("client-bad-protocol", 1)
		return fmt.Errorf("unrecognized initial packet = % 02x", buf)
	}

	// Dial & verify upstream connection.
	var d net.Dialer
	d.Timeout = 10 * time.Second
	upstreamConn, err := d.Dial("tcp", p.upstreamAddr)
	if err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("upstream dial: %v", err)
	}
	defer upstreamConn.Close()
	if _, err := upstreamConn.Write(sslStart[:]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("upstream write of start-ssl magic: %v", err)
	}
	if _, err := io.ReadFull(upstreamConn, buf[:1]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("reading upstream start-ssl response: %v", err)
	}
	if buf[0] != 'S' {
		p.errors.Add("upstream-bad-protocol", 1)
		return fmt.Errorf("upstream didn't acknowledge start-ssl, said %q", buf[0])
	}
	tlsConf := &tls.Config{
		ServerName: p.upstreamHost,
		RootCAs:    p.upstreamCertPool,
		MinVersion: tls.VersionTLS12,
	}
	upstreamTLSConn := tls.Client(upstreamConn, tlsConf)
	// No need to "defer Close" upstreamTLSConn
	if err = upstreamTLSConn.HandshakeContext(ctx); err != nil {
		p.errors.Add("upstream-tls", 1)
		return fmt.Errorf("upstream TLS handshake: %v", err)
	}
	log.Print("Upstream TLS handshake complete")

	// This proxy acts as backend for the client connection
	var backend *pgproto3.Backend

	// Accept the client conn and set it up the way the client wants.
	if clientIsTLS {
		io.WriteString(clientConn, "S") // yeah, we're good to speak TLS
		secureClientConn := tls.Server(clientConn, &tls.Config{
			ServerName:   p.upstreamHost,
			Certificates: p.downstreamCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err = upstreamTLSConn.HandshakeContext(ctx); err != nil {
			p.errors.Add("client-tls", 1)
			return fmt.Errorf("client TLS handshake: %v", err)
		}
		backend = pgproto3.NewBackend(pgproto3.NewChunkReader(secureClientConn), secureClientConn)
	} else {
		// For non-TLS connections the first 8 bytes were already consumed; prepend them.
		clientReader := io.MultiReader(bytes.NewReader(plaintextStart[:]), clientConn)
		backend = pgproto3.NewBackend(pgproto3.NewChunkReader(clientReader), clientConn)
	}

	// This proxy acts as frontend to the upstream database server
	frontend := pgproto3.NewFrontend(pgproto3.NewChunkReader(upstreamTLSConn), upstreamTLSConn)

	// If the connecting Tailscale user is a GMail address, substitute credentials
	// with fixed values regardless of what the client sends.
	if strings.HasSuffix(tailscaleUser, "@gmail.com") {
		log.Printf("Recognized user %s", tailscaleUser)
	} else {

	}
	err = p.interceptAuth(frontend, backend, tailscaleUser)
	if err != nil {
		p.errors.Add("auth-intercept", 1)
		return fmt.Errorf("auth intercept for %s: %v", tailscaleUser, err)
	}

	log.Print("Started proxying data")

	// Finally, proxy the client to the upstream.
	errc := make(chan error, 1)
	go func() {
		// Proxy requests to the Postgres server, logging SQL statements.
		err := logAndProxy(sessionID, frontend, backend)
		errc <- err
	}()
	go func() {
		// Proxy responses back to the client.
		err := proxyServerResponses(frontend, backend)
		errc <- err
	}()
	if err := <-errc; err != nil {
		// Don't increment error counts here, because the most common
		// cause of termination is client or server closing the
		// connection normally, and it'll obscure "interesting"
		// handshake errors.
		return fmt.Errorf("session terminated with error: %v", err)
	}
	return nil
}

// logAndProxy reads PostgreSQL wire protocol messages from src, logs any SQL
// statements ('Q' simple queries and 'P' prepared statements), and forwards
// all messages verbatim to dst.
func logAndProxy(sessionID int64, frontend *pgproto3.Frontend, backend *pgproto3.Backend) error {
	for {
		msg, err := backend.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			log.Printf("%d: query: %s", sessionID, m.String)
		case *pgproto3.Parse:
			log.Printf("%d: prepare: %s", sessionID, m.Query)
		}
		if err := frontend.Send(msg); err != nil {
			return err
		}
	}
}

func proxyServerResponses(frontend *pgproto3.Frontend, backend *pgproto3.Backend) error {
	for {
		msg, err := frontend.Receive()
		if err != nil {
			return err
		}
		if err := backend.Send(msg); err != nil {
			return err
		}
	}
}

// interceptAuth reads the client's PostgreSQL startup message, rewrites the
// user field, forwards it to upstream, handles the upstream auth challenge
// using the injected password, then sends AuthOk to the client.
func (p *proxy) interceptAuth(frontend *pgproto3.Frontend, backend *pgproto3.Backend, tailscaleUser string) error {
	startupMsg, err := backend.ReceiveStartupMessage()

	if err != nil {
		return fmt.Errorf("reading startup message: %v", err)
	}
	startup, ok := startupMsg.(*pgproto3.StartupMessage)
	if !ok {
		return fmt.Errorf("unexpected startup message type: %T", startupMsg)
	}
	log.Printf("Received startup message of length with parameters %v", startup.Parameters)

	var postgresUser string
	var postgresPass string
	if tailscaleUser == "" { // no tailscale user
		postgresUser = startup.Parameters["user"]
		postgresPass = startup.Parameters["password"]
	} else {
		postgresUser = "ro"
		postgresPass = "my-secret"
		if tailscaleUser == "foo" { // Here we can check which users have read/write permissions
			postgresUser = "rw"
			postgresPass = "do-not-share"
		}

		startup.Parameters["user"] = postgresUser
		if appName, exists := startup.Parameters["application_name"]; exists {
			startup.Parameters["application_name"] = appName + " - " + tailscaleUser
		} else {
			startup.Parameters["application_name"] = tailscaleUser
		}
	}

	if err := frontend.Send(startup); err != nil {
		return fmt.Errorf("sending startup to upstream: %v", err)
	}

	if err := handleUpstreamAuth(frontend, postgresUser, postgresPass); err != nil {
		return fmt.Errorf("upstream auth: %v", err)
	}

	if err := backend.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return fmt.Errorf("sending auth ok to client: %v", err)
	}
	return nil
}

// handleUpstreamAuth handles the PostgreSQL authentication exchange, responding
// to the upstream's challenge with the given credentials. Returns nil on AuthOk.
func handleUpstreamAuth(frontend *pgproto3.Frontend, username, password string) error {
	msg, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("reading auth message: %v", err)
	}
	switch m := msg.(type) {
	case *pgproto3.AuthenticationOk:
		log.Print("Authentication successful")
		return nil
	case *pgproto3.AuthenticationCleartextPassword:
		log.Print("Authentication with clear text password")
		if err := frontend.Send(&pgproto3.PasswordMessage{Password: password}); err != nil {
			return fmt.Errorf("sending cleartext password: %v", err)
		}
	case *pgproto3.AuthenticationMD5Password:
		log.Print("Authentication with MD5 hashed password")
		inner := md5.Sum([]byte(password + username))
		innerHex := fmt.Sprintf("%x", inner)
		outer := md5.Sum(append([]byte(innerHex), m.Salt[:]...))
		hashed := "md5" + fmt.Sprintf("%x", outer)
		if err := frontend.Send(&pgproto3.PasswordMessage{Password: hashed}); err != nil {
			return fmt.Errorf("sending MD5 password: %v", err)
		}
	default:
		return fmt.Errorf("unsupported authentication method: %T", msg)
	}

	result, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("reading auth result: %v", err)
	}
	if _, ok := result.(*pgproto3.AuthenticationOk); !ok {
		return fmt.Errorf("authentication failed: %T", result)
	}
	return nil
}

// mkSelfSigned creates and returns a self-signed TLS certificate for
// hostname.
func mkSelfSigned(hostname string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	pub := priv.Public()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"pgproxy"},
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(crand.Reader, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}
