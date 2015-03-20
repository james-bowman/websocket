// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package websocket

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"encoding/base64"
	"fmt"
	"bufio"
)

// ErrBadHandshake is returned when the server response to opening handshake is
// invalid.
var ErrBadHandshake = errors.New("websocket: bad handshake")

// NewClient creates a new client connection using the given net connection.
// The URL u specifies the host and request URI. Use requestHeader to specify
// the origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies
// (Cookie). Use the response.Header to get the selected subprotocol
// (Sec-WebSocket-Protocol) and cookies (Set-Cookie).
//
// If the WebSocket handshake fails, ErrBadHandshake is returned along with a
// non-nil *http.Response so that callers can handle redirects, authentication,
// etc.
func NewClient(netConn net.Conn, u *url.URL, requestHeader http.Header, readBufSize, writeBufSize int) (c *Conn, response *http.Response, err error) {
	challengeKey, err := generateChallengeKey()
	if err != nil {
		return nil, nil, err
	}
	acceptKey := computeAcceptKey(challengeKey)

	c = newConn(netConn, false, readBufSize, writeBufSize)
	p := c.writeBuf[:0]
	p = append(p, "GET "...)
	p = append(p, u.RequestURI()...)
	p = append(p, " HTTP/1.1\r\nHost: "...)
	p = append(p, u.Host...)
	// "Upgrade" is capitalized for servers that do not use case insensitive
	// comparisons on header tokens.
	p = append(p, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "...)
	p = append(p, challengeKey...)
	p = append(p, "\r\n"...)
	for k, vs := range requestHeader {
		for _, v := range vs {
			p = append(p, k...)
			p = append(p, ": "...)
			p = append(p, v...)
			p = append(p, "\r\n"...)
		}
	}
	p = append(p, "\r\n"...)

	if _, err := netConn.Write(p); err != nil {
		return nil, nil, err
	}

	resp, err := http.ReadResponse(c.br, &http.Request{Method: "GET", URL: u})
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != 101 ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!strings.EqualFold(resp.Header.Get("Connection"), "upgrade") ||
		resp.Header.Get("Sec-Websocket-Accept") != acceptKey {
		return nil, resp, ErrBadHandshake
	}
	c.subprotocol = resp.Header.Get("Sec-Websocket-Protocol")
	return c, resp, nil
}

// A Dialer contains options for connecting to WebSocket server.
type Dialer struct {
	// NetDial specifies the dial function for creating TCP connections. If
	// NetDial is nil, net.Dial is used.
	NetDial func(network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// Input and output buffer sizes. If the buffer size is zero, then a
	// default value of 4096 is used.
	ReadBufferSize, WriteBufferSize int

	// Subprotocols specifies the client's requested subprotocols.
	Subprotocols []string
}

var errMalformedURL = errors.New("malformed ws or wss URL")

// parseURL parses the URL. The url.Parse function is not used here because
// url.Parse mangles the path.
func parseURL(s string) (*url.URL, error) {
	// From the RFC:
	//
	// ws-URI = "ws:" "//" host [ ":" port ] path [ "?" query ]
	// wss-URI = "wss:" "//" host [ ":" port ] path [ "?" query ]
	//
	// We don't use the net/url parser here because the dialer interface does
	// not provide a way for applications to work around percent deocding in
	// the net/url parser.

	var u url.URL
	switch {
	case strings.HasPrefix(s, "ws://"):
		u.Scheme = "ws"
		s = s[len("ws://"):]
	case strings.HasPrefix(s, "wss://"):
		u.Scheme = "wss"
		s = s[len("wss://"):]
	default:
		return nil, errMalformedURL
	}

	u.Host = s
	u.Opaque = "/"
	if i := strings.Index(s, "/"); i >= 0 {
		u.Host = s[:i]
		u.Opaque = s[i:]
	}

	return &u, nil
}

func hostPortNoPort(u *url.URL) (hostPort, hostNoPort string) {
	hostPort = u.Host
	hostNoPort = u.Host
	if i := strings.LastIndex(u.Host, ":"); i > strings.LastIndex(u.Host, "]") {
		hostNoPort = hostNoPort[:i]
	} else {
		if u.Scheme == "wss" {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}
	return hostPort, hostNoPort
}

// DefaultDialer is a dialer with all fields set to the default zero values.
var DefaultDialer *Dialer

// Dial creates a new client connection. Use requestHeader to specify the
// origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies (Cookie).
// Use the response.Header to get the selected subprotocol
// (Sec-WebSocket-Protocol) and cookies (Set-Cookie).
//
// If the WebSocket handshake fails, ErrBadHandshake is returned along with a
// non-nil *http.Response so that callers can handle redirects, authentication,
// etc.
func (d *Dialer) Dial(urlStr string, requestHeader http.Header) (*Conn, *http.Response, error) {
	u, err := parseURL(urlStr)
	if err != nil {
		return nil, nil, err
	}

	hostPort, hostNoPort := hostPortNoPort(u)

	if d == nil {
		d = &Dialer{}
	}

	var deadline time.Time
	if d.HandshakeTimeout != 0 {
		deadline = time.Now().Add(d.HandshakeTimeout)
	}

	netDial := d.NetDial
	if netDial == nil {
		netDialer := &net.Dialer{Deadline: deadline}
		netDial = netDialer.Dial
	}

	// setup proxy
	// TODO
	cm, err := connectMethodForRequest(u, hostPort, requestHeader)

	if err != nil {
		return nil, nil, fmt.Errorf("Error getting connect Method for %s: %v", hostPort, err)
	}

	netConn, err := netDial("tcp", cm.addr())
	if err != nil {
		if cm.proxyURL != nil {
			err = fmt.Errorf("error connecting to proxy %s: %v", cm.proxyURL, err)
		}
		return nil, nil, fmt.Errorf("Error during dial to %s: %v", cm.addr(), err)
	}

	defer func() {
		if netConn != nil {
			netConn.Close()
		}
	}()

	// Proxy setup.
	switch {
	case cm.proxyURL == nil:
		// Do nothing. Not using a proxy.
/*	
	case cm.targetScheme == "ws":
		pconn.isProxy = true
		if pa := cm.proxyAuth(); pa != "" {
			pconn.mutateHeaderFunc = func(h Header) {
				h.Set("Proxy-Authorization", pa)
			}
		}
*/	
	case cm.targetScheme == "wss":
		connectReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: cm.targetAddr},
			Host:   cm.targetAddr,
			Header: make(http.Header),
		}
		if pa := cm.proxyAuth(); pa != "" {
			connectReq.Header.Set("Proxy-Authorization", pa)
		}
		connectReq.Write(netConn)

		// Read response.
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(netConn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			return nil, nil, fmt.Errorf("Error reading response %s: %v", hostPort, err)
		}
		if resp.StatusCode != 200 {
			f := strings.SplitN(resp.Status, " ", 2)
			return nil, nil, errors.New(f[1])
		}
	}

	if err := netConn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}

	if u.Scheme == "wss" {
		cfg := d.TLSClientConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: hostNoPort}
		} else if cfg.ServerName == "" {
			shallowCopy := *cfg
			cfg = &shallowCopy
			cfg.ServerName = hostNoPort
		}
		tlsConn := tls.Client(netConn, cfg)
		netConn = tlsConn
		if err := tlsConn.Handshake(); err != nil {
			return nil, nil, err
		}
		if !cfg.InsecureSkipVerify {
			if err := tlsConn.VerifyHostname(cfg.ServerName); err != nil {
				return nil, nil, err
			}
		}
	}

	if len(d.Subprotocols) > 0 {
		h := http.Header{}
		for k, v := range requestHeader {
			h[k] = v
		}
		h.Set("Sec-Websocket-Protocol", strings.Join(d.Subprotocols, ", "))
		requestHeader = h
	}

	conn, resp, err := NewClient(netConn, u, requestHeader, d.ReadBufferSize, d.WriteBufferSize)
	if err != nil {
		return nil, resp, err
	}

	netConn.SetDeadline(time.Time{})
	netConn = nil // to avoid close in defer.
	return conn, resp, nil
}

func connectMethodForRequest(u *url.URL, hostPort string, requestHeader http.Header) (cm connectMethod, err error) {
	req := &http.Request{
			Method: "GET",
			URL:    u,
			Host:   hostPort,
			Header: requestHeader,
	}

	cm.targetScheme = u.Scheme
	cm.targetAddr = canonicalAddr(u)
	cm.proxyURL, err = http.ProxyFromEnvironment(req)
	return cm, err
}

type connectMethod struct {
	proxyURL     *url.URL // nil for no proxy, else full proxy URL
	targetScheme string   // "http" or "https"
	targetAddr   string   // Not used if proxy + http targetScheme (4th example in table)
}

// proxyAuth returns the Proxy-Authorization header to set
// on requests, if applicable.
func (cm *connectMethod) proxyAuth() string {
	if cm.proxyURL == nil {
		return ""
	}
	if u := cm.proxyURL.User; u != nil {
		username := u.Username()
		password, _ := u.Password()
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	}
	return ""
}

// addr returns the first hop "host:port" to which we need to TCP connect.
func (cm *connectMethod) addr() string {
	if cm.proxyURL != nil {
		return canonicalAddr(cm.proxyURL)
	}
	return cm.targetAddr
}

// tlsHost returns the host name to match against the peer's
// TLS certificate.
func (cm *connectMethod) tlsHost() string {
	h := cm.targetAddr
	if hasPort(h) {
		h = h[:strings.LastIndex(h, ":")]
	}
	return h
}

var portMap = map[string]string{
	"http":  "80",
	"https": "443",
	"ws": "80",
	"wss": "443",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Host
	if !hasPort(addr) {
		return addr + ":" + portMap[url.Scheme]
	}
	return addr
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }