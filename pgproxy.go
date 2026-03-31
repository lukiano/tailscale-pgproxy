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
	"encoding/binary"
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
func (p *proxy) serve(sessionID int64, c net.Conn) error {
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	whois, err := p.client.WhoIs(ctx, c.RemoteAddr().String())
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
	log.Printf("%d: session start, from %s (machine %s, user %s)", sessionID, c.RemoteAddr(), machine, tailscaleUser)
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf("%d: session end, from %s (machine %s, user %s), lasted %s", sessionID, c.RemoteAddr(), machine, tailscaleUser, elapsed.Round(time.Millisecond))
	}()

	// Read the client's opening message, to figure out if it's trying
	// to TLS or not.
	var buf [8]byte
	if _, err := io.ReadFull(c, buf[:len(sslStart)]); err != nil {
		p.errors.Add("network-error", 1)
		return fmt.Errorf("initial magic read: %v", err)
	}
	var clientIsTLS bool
	switch {
	case buf == sslStart:
		clientIsTLS = true
	case buf == plaintextStart:
		clientIsTLS = false
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
	if err = upstreamTLSConn.HandshakeContext(ctx); err != nil {
		p.errors.Add("upstream-tls", 1)
		return fmt.Errorf("upstream TLS handshake: %v", err)
	}

	// Accept the client conn and set it up the way the client wants.
	var clientConn net.Conn
	if clientIsTLS {
		io.WriteString(c, "S") // yeah, we're good to speak TLS
		s := tls.Server(c, &tls.Config{
			ServerName:   p.upstreamHost,
			Certificates: p.downstreamCert,
			MinVersion:   tls.VersionTLS12,
		})
		if err = upstreamTLSConn.HandshakeContext(ctx); err != nil {
			p.errors.Add("client-tls", 1)
			return fmt.Errorf("client TLS handshake: %v", err)
		}
		clientConn = s
	} else {
		clientConn = c
	}

	// If the connecting Tailscale user is a GMail address, substitute credentials
	// with fixed values regardless of what the client sends.
	if strings.HasSuffix(tailscaleUser, "@gmail.com") {
		if err := p.interceptAuth(clientConn, upstreamTLSConn, clientIsTLS, tailscaleUser); err != nil {
			p.errors.Add("auth-intercept", 1)
			return fmt.Errorf("auth intercept for %s: %v", tailscaleUser, err)
		}
	} else if !clientIsTLS {
		// For non-intercepted plaintext sessions, forward the startup header we already read.
		if _, err := upstreamTLSConn.Write(plaintextStart[:]); err != nil {
			p.errors.Add("network-error", 1)
			return fmt.Errorf("sending initial client bytes to upstream: %v", err)
		}
	}

	// Finally, proxy the client to the upstream.
	errc := make(chan error, 1)
	go func() {
		// Proxy requests to the Postgres server.
		_, err := io.Copy(upstreamTLSConn, clientConn)
		errc <- err
	}()
	go func() {
		// Proxy responses back to the client.
		_, err := io.Copy(clientConn, upstreamTLSConn)
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

// interceptAuth reads the client's PostgreSQL startup message, rewrites the
// user field to "ro", forwards it to upstream, handles the upstream auth
// challenge using the injected password, then sends AuthOk to the client.
func (p *proxy) interceptAuth(clientConn net.Conn, upstream net.Conn, clientIsTLS bool, tailscaleUser string) error {
	var startupMsg []byte
	if clientIsTLS {
		// After TLS handshake the client sends a fresh startup message.
		var lenBuf [4]byte
		if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
			return fmt.Errorf("reading startup length: %v", err)
		}
		msgLen := int(binary.BigEndian.Uint32(lenBuf[:]))
		if msgLen < 8 || msgLen > 65536 {
			return fmt.Errorf("invalid startup message length: %d", msgLen)
		}
		startupMsg = make([]byte, msgLen)
		copy(startupMsg, lenBuf[:])
		if _, err := io.ReadFull(clientConn, startupMsg[4:]); err != nil {
			return fmt.Errorf("reading startup message: %v", err)
		}
	} else {
		// We already read the first 8 bytes (plaintextStart); read the rest.
		totalLen := int(binary.BigEndian.Uint32(plaintextStart[:4]))
		if totalLen < 8 || totalLen > 65536 {
			return fmt.Errorf("invalid startup message length: %d", totalLen)
		}
		startupMsg = make([]byte, totalLen)
		copy(startupMsg, plaintextStart[:])
		if totalLen > 8 {
			if _, err := io.ReadFull(clientConn, startupMsg[8:]); err != nil {
				return fmt.Errorf("reading startup message remainder: %v", err)
			}
		}
	}

	newStartup, err := rewriteStartupUser(startupMsg, "ro", tailscaleUser)
	if err != nil {
		return fmt.Errorf("rewriting startup: %v", err)
	}
	if _, err := upstream.Write(newStartup); err != nil {
		return fmt.Errorf("sending startup to upstream: %v", err)
	}
	postgresUser := "ro"
	postgresPass := "my-secret"
	if tailscaleUser == "foo" { // Here we can check which users have read/write permissions
		postgresUser = "rw"
		postgresPass = "do-not-share"
	}
	if err := handleUpstreamAuth(upstream, postgresUser, postgresPass); err != nil {
		return fmt.Errorf("upstream auth: %v", err)
	}

	// Tell the client auth succeeded.
	// PostgreSQL AuthenticationOk: 'R' + int32(8) + int32(0)
	authOk := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	if _, err := clientConn.Write(authOk); err != nil {
		return fmt.Errorf("sending auth ok to client: %v", err)
	}
	return nil
}

// rewriteStartupUser returns a copy of the PostgreSQL startup message with the
// "user" parameter replaced by postgresUser. All other parameters are preserved.
func rewriteStartupUser(msg []byte, postgresUser string, tailscaleUser string) ([]byte, error) {
	if len(msg) < 8 {
		return nil, fmt.Errorf("startup message too short (%d bytes)", len(msg))
	}
	// msg[0:4] = total length; msg[4:8] = protocol version (preserved)
	protocol := msg[4:8]

	params := make(map[string]string)
	keys := make([]string, 0)
	rest := msg[8:]
	for len(rest) > 0 && rest[0] != 0 {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, fmt.Errorf("malformed startup message: unterminated key")
		}
		key := string(rest[:end])
		rest = rest[end+1:]
		end = bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, fmt.Errorf("malformed startup message: unterminated value for %q", key)
		}
		val := string(rest[:end])
		rest = rest[end+1:]
		if _, exists := params[key]; !exists {
			keys = append(keys, key)
		}
		params[key] = val
	}

	if _, exists := params["user"]; !exists {
		keys = append(keys, "user")
	}
	params["user"] = postgresUser

	// Append user to application name
	if _, exists := params["application_name"]; exists {
		params["application_name"] = params["application_name"] + " - " + tailscaleUser
	} else {
		keys = append(keys, "application_name")
		params["application_name"] = tailscaleUser

	}

	var body []byte
	body = append(body, protocol...)
	for _, k := range keys {
		body = append(body, k...)
		body = append(body, 0)
		body = append(body, params[k]...)
		body = append(body, 0)
	}
	body = append(body, 0) // message terminator

	newMsg := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(newMsg[:4], uint32(len(newMsg)))
	copy(newMsg[4:], body)
	return newMsg, nil
}

// handleUpstreamAuth handles the PostgreSQL authentication exchange, responding
// to the upstream's challenge with the given credentials. Returns nil on AuthOk.
func handleUpstreamAuth(upstream net.Conn, username, password string) error {
	var typeBuf [1]byte
	var lenBuf [4]byte

	if _, err := io.ReadFull(upstream, typeBuf[:]); err != nil {
		return fmt.Errorf("reading auth message type: %v", err)
	}
	if typeBuf[0] != 'R' {
		return fmt.Errorf("expected auth message ('R'), got %q", typeBuf[0])
	}
	if _, err := io.ReadFull(upstream, lenBuf[:]); err != nil {
		return fmt.Errorf("reading auth message length: %v", err)
	}
	bodyLen := int(binary.BigEndian.Uint32(lenBuf[:])) - 4
	if bodyLen < 4 {
		return fmt.Errorf("auth message body too short")
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(upstream, body); err != nil {
		return fmt.Errorf("reading auth message body: %v", err)
	}

	authType := binary.BigEndian.Uint32(body[:4])
	switch authType {
	case 0:
		return nil // AuthenticationOk — no password needed
	case 3:
		// AuthenticationCleartextPassword
		pw := append([]byte(password), 0)
		msg := make([]byte, 5+len(pw))
		msg[0] = 'p'
		binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(pw)))
		copy(msg[5:], pw)
		if _, err := upstream.Write(msg); err != nil {
			return fmt.Errorf("sending cleartext password: %v", err)
		}
	case 5:
		// AuthenticationMD5Password — salt is body[4:8]
		if len(body) < 8 {
			return fmt.Errorf("MD5 auth message too short")
		}
		salt := body[4:8]
		inner := md5.Sum([]byte(password + username))
		innerHex := fmt.Sprintf("%x", inner)
		outer := md5.Sum(append([]byte(innerHex), salt...))
		hashed := "md5" + fmt.Sprintf("%x", outer)
		pw := append([]byte(hashed), 0)
		msg := make([]byte, 5+len(pw))
		msg[0] = 'p'
		binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(pw)))
		copy(msg[5:], pw)
		if _, err := upstream.Write(msg); err != nil {
			return fmt.Errorf("sending MD5 password: %v", err)
		}
	default:
		return fmt.Errorf("unsupported authentication method: %d", authType)
	}

	// Read auth result after sending password.
	if _, err := io.ReadFull(upstream, typeBuf[:]); err != nil {
		return fmt.Errorf("reading auth result type: %v", err)
	}
	if typeBuf[0] != 'R' {
		return fmt.Errorf("expected auth result ('R'), got %q", typeBuf[0])
	}
	if _, err := io.ReadFull(upstream, lenBuf[:]); err != nil {
		return fmt.Errorf("reading auth result length: %v", err)
	}
	resultBodyLen := int(binary.BigEndian.Uint32(lenBuf[:])) - 4
	if resultBodyLen < 4 {
		return fmt.Errorf("auth result body too short")
	}
	result := make([]byte, resultBodyLen)
	if _, err := io.ReadFull(upstream, result); err != nil {
		return fmt.Errorf("reading auth result: %v", err)
	}
	if binary.BigEndian.Uint32(result[:4]) != 0 {
		return fmt.Errorf("authentication failed")
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
