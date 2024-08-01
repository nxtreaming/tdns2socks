package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

/**
 * @Author: gedebin
 * @Date: 2024/8/1 10:15
 * @Desc:
 */

var (
	configDnsMu   sync.RWMutex
	configProxyMu sync.RWMutex
)

// DNSHandler handles DNS requests
func DNSHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	if len(req.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	question := req.Question[0]
	domain := question.Name

	// Only process "A Record"
	if question.Qtype != dns.TypeA {
		m.SetRcode(req, dns.RcodeNotImplemented)
		w.WriteMsg(m)
		return
	}

	sourceIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	// Check cache
	cache, exists := cacheMap[sourceIP]
	if !exists {
		cache = NewCache()
		cacheMap[sourceIP] = cache
	}

	if cachedMsg, found := cache.Get(domain); found {
		logrus.Infof("Cache hit for domain: %s from source IP: %s", domain, sourceIP)
		m.Answer = cachedMsg.Answer
		w.WriteMsg(m)
		return
	}

	// Perform DNS query
	configProxyMu.RLock()
	config, exists := proxyConfigMap[sourceIP]
	configProxyMu.RUnlock()

	if !exists {
		config, exists = proxyConfigMap["default"]
		if !exists {
			m.SetRcode(req, dns.RcodeRefused)
			w.WriteMsg(m)
			return
		}
	}

	configDnsMu.RLock()
	upstreamDNSConfig, exists := upstreamDNSMap[sourceIP]
	if !exists {
		upstreamDNSConfig = UpDNSConfig{UpDNS: Config.ProxyDefault.Upstream}
	}
	upDNS := upstreamDNSConfig.UpDNS
	configDnsMu.RUnlock()

	logrus.Debugf("Received DNS query for domain: %s from source IP: %s", domain, sourceIP)

	response, err := QueryDNS(domain, config, upDNS)
	if err != nil {
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		logrus.Errorf("DNS query for domain: %s from IP: %s failed with error: %v", domain, sourceIP, err)
		return
	}

	// Update cache
	cache.Put(domain, response)

	m.Answer = response.Answer
	logrus.Debugf("Writing DNS response for domain: %s", domain)
	if err := w.WriteMsg(m); err != nil {
		logrus.Errorf("Failed to write DNS response: %v", err)
	}
}

// QueryDNS queries DNS through a SOCKS5 proxy using the specified protocol (TCP or UDP)
func QueryDNS(domain string, config ProxyConfig, upDNS string) (*dns.Msg, error) {
	if config.Protocol == "tcp" {
		// Create a SOCKS5 dialer
		proxyAddr := net.JoinHostPort(config.Server, strconv.Itoa(config.Port))
		auth := &proxy.Auth{
			User:     config.Username,
			Password: config.Password,
		}
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
		if err != nil {
			logrus.Errorf("Failed to create SOCKS5 dialer: %v", err)
			return nil, err
		}
		return queryTCP(domain, dialer, upDNS)
	} else if config.Protocol == "udp" {
		return queryUDP(domain, config, upDNS)
	}

	return nil, fmt.Errorf("Unsupported protocol: %s", config.Protocol)
}

// executeDNSQuery performs the DNS query based on the protocol
func executeDNSQuery(domain string, conn net.Conn, upDNS, protocol string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	buf, err := msg.Pack()
	if err != nil {
		logrus.Errorf("Failed to pack DNS query: %v", err)
		return nil, err
	}

	if protocol == "tcp" {
		return executeDNSQueryTCP(domain, conn, buf)
	} else if protocol == "udp" {
		return executeDNSQueryUDP(domain, conn, buf, upDNS)
	}

	return nil, fmt.Errorf("Unsupported protocol: %s", protocol)
}

// executeDNSQueryTCP performs the DNS query over TCP
func executeDNSQueryTCP(domain string, conn net.Conn, buf []byte) (*dns.Msg, error) {
	// Prepend the length of the DNS query (2 bytes) for TCP transport
	tcpBuf := make([]byte, 2+len(buf))
	tcpBuf[0] = byte(len(buf) >> 8)
	tcpBuf[1] = byte(len(buf))
	copy(tcpBuf[2:], buf)

	// Send DNS query
	logrus.Debugf("Sending DNS query for domain: %s using protocol: tcp", domain)
	if _, err := conn.Write(tcpBuf); err != nil {
		logrus.Errorf("Failed to write to connection: %v", err)
		return nil, err
	}

	// Read DNS response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuf := make([]byte, 1024) // Increase buffer size for larger responses
	n, err := conn.Read(responseBuf)
	if err != nil || n < 2+minDNSResponseLength {
		logrus.Errorf("Failed to read response: %v", err)
		if n > 0 {
			logrus.Warnf("Partial response received: %x", responseBuf[:n])
		}
		return nil, err
	}
	logrus.Debugf("Received response length: %d, data:%x", n, responseBuf[:n])

	// Remove the length prefix before unpacking the response
	response := new(dns.Msg)
	if err := response.Unpack(responseBuf[2:n]); err != nil {
		logrus.Errorf("Failed to unpack DNS response: %v", err)
		return nil, err
	}

	logrus.Infof("DNS query by TCP for domain: %s succeeded. Response: %v", domain, extractAnswerSection(response))
	return response, nil
}

// executeDNSQueryUDP performs the DNS query over UDP
func executeDNSQueryUDP(domain string, conn net.Conn, buf []byte, upDNS string) (*dns.Msg, error) {
	targetAddr, err := net.ResolveUDPAddr("udp", upDNS)
	if err != nil {
		logrus.Errorf("Failed to resolve target address: %v", err)
		return nil, err
	}
	logrus.Debugf("Resolved target address: %v", targetAddr)

	// Prepare the UDP packet
	var udpBuf bytes.Buffer
	udpBuf.WriteByte(0x00) // RSV
	udpBuf.WriteByte(0x00) // RSV
	udpBuf.WriteByte(0x00) // FRAG
	udpBuf.WriteByte(0x01) // ATYP (IPv4)
	udpBuf.Write(targetAddr.IP.To4())
	binary.Write(&udpBuf, binary.BigEndian, uint16(targetAddr.Port))
	udpBuf.Write(buf)

	logrus.Debugf("Constructed UDP packet data: %x", udpBuf.Bytes())

	// Send UDP packet to SOCKS5 proxy server
	logrus.Debugf("Sending UDP packet to proxy server")
	if _, err := conn.(*net.UDPConn).Write(udpBuf.Bytes()); err != nil {
		logrus.Errorf("Failed to send UDP data: %v", err)
		return nil, err
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Receive response
	responseBuf := make([]byte, 1024)
	n, addr, err := conn.(*net.UDPConn).ReadFrom(responseBuf)
	if err != nil {
		logrus.Errorf("Failed to read UDP response: %v", err)
		return nil, err
	}
	logrus.Debugf("Received UDP response from %v, data: %x", addr, responseBuf[:n])

	// Remove the SOCKS5 UDP header and check for a minimum DNS response length
	if n < 10+minDNSResponseLength {
		return nil, fmt.Errorf("invalid UDP response length")
	}
	udpResponseData := responseBuf[10:n]

	// Unpack the response
	response := new(dns.Msg)
	if err := response.Unpack(udpResponseData); err != nil {
		logrus.Errorf("Failed to unpack DNS response: %v", err)
		logrus.Errorf("UDP response data: %x", udpResponseData)
		return nil, err
	}

	logrus.Infof("DNS query by UDP for domain: %s succeeded. Response: %v", domain, extractAnswerSection(response))
	return response, nil
}

// queryTCP handles DNS queries over TCP
func queryTCP(domain string, dialer proxy.Dialer, upDNS string) (*dns.Msg, error) {
	conn, err := dialer.Dial("tcp", upDNS)
	if err != nil {
		logrus.Errorf("Failed to dial to upstream DNS server: %v", err)
		return nil, err
	}
	defer conn.Close()

	return executeDNSQuery(domain, conn, upDNS, "tcp")
}

// socks5UDPAssociate performs a UDP ASSOCIATE request to the SOCKS5 proxy
func socks5UDPAssociate(proxyAddr, username, password string) (*net.UDPConn, net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to proxy: %v", err)
	}
	logrus.Debugf("Connected to SOCKS5 proxy at %s", proxyAddr)

	var authCode byte = 0x00
	if username != "" && password != "" {
		authCode = 0x02
	}

	// Initial handshake
	_, err = conn.Write([]byte{0x05, 0x01, authCode})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to write initial handshake: %v", err)
	}

	// Read handshake response
	response := make([]byte, 2)
	_, err = conn.Read(response)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to read initial handshake response: %v", err)
	}

	if response[0] != 0x05 || response[1] != authCode {
		conn.Close()
		return nil, nil, fmt.Errorf("unexpected initial handshake response: %v", response)
	}

	if authCode != 0x00 {
		// Username/Password authentication
		authMsg := []byte{0x01, byte(len(username))}
		authMsg = append(authMsg, []byte(username)...)
		authMsg = append(authMsg, byte(len(password)))
		authMsg = append(authMsg, []byte(password)...)

		_, err = conn.Write(authMsg)
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("failed to write auth message: %v", err)
		}

		// Read auth response
		authResponse := make([]byte, 2)
		_, err = conn.Read(authResponse)
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("failed to read auth response: %v", err)
		}

		if authResponse[0] != 0x01 || authResponse[1] != 0x00 {
			conn.Close()
			return nil, nil, fmt.Errorf("auth failed: %v", authResponse)
		}
	}
	logrus.Debugf("SOCKS5 handshake completed")

	// Send UDP ASSOCIATE request
	udpRequest := []byte{
		0x05, 0x03, 0x00, 0x01, // SOCKS5, UDP ASSOCIATE, reserved, IPv4
		0x00, 0x00, 0x00, 0x00, // 0.0.0.0 (address)
		0x00, 0x00, // 0 (port)
	}
	_, err = conn.Write(udpRequest)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to send UDP ASSOCIATE request: %v", err)
	}
	logrus.Debugf("UDP ASSOCIATE request sent")

	response = make([]byte, 10)
	_, err = conn.Read(response)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to read UDP ASSOCIATE response: %v", err)
	}
	logrus.Debugf("UDP ASSOCIATE response received: %v", response)

	if response[1] != 0x00 {
		conn.Close()
		return nil, nil, fmt.Errorf("UDP ASSOCIATE request failed: %v", response[1])
	}

	proxyIP := net.IPv4(response[4], response[5], response[6], response[7])
	proxyPort := binary.BigEndian.Uint16(response[8:10])
	proxyUDPAddr := &net.UDPAddr{
		IP:   proxyIP,
		Port: int(proxyPort),
	}
	logrus.Debugf("Proxy UDP address: %v", proxyUDPAddr)

	udpConn, err := net.DialUDP("udp", nil, proxyUDPAddr)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to dial UDP: %v", err)
	}

	return udpConn, conn, nil
}

// queryUDP handles DNS queries over UDP
func queryUDP(domain string, proxyConfig ProxyConfig, upDNS string) (*dns.Msg, error) {
	proxyAddr := net.JoinHostPort(proxyConfig.Server, strconv.Itoa(proxyConfig.Port))
	udpConn, tcpConn, err := socks5UDPAssociate(proxyAddr, proxyConfig.Username, proxyConfig.Password)
	if err != nil {
		logrus.Errorf("UDP ASSOCIATE failed: %v", err)
		return nil, err
	}
	defer udpConn.Close()
	// Close the TCP connection after UDP communication is done, The UDP communication
	// would be closed immediately by socks5 sever if the TCP connection is closed.
	defer tcpConn.Close()

	return executeDNSQuery(domain, udpConn, upDNS, "udp")
}

// extractAnswerSection extracts IPs from the Answer Section
func extractAnswerSection(response *dns.Msg) string {
	if response == nil {
		return ""
	}

	var answerLines []string
	for _, ans := range response.Answer {
		// Convert the answer to string and replace tabs with spaces
		cleanedAnswer := strings.ReplaceAll(ans.String(), "\t", " ")

		// Split the cleaned answer line into parts
		parts := strings.Fields(cleanedAnswer)

		// Extract the relevant parts (domain and IP address)
		if len(parts) >= 5 {
			filteredAnswer := fmt.Sprintf("%s %s %s", parts[0], parts[3], parts[4])
			answerLines = append(answerLines, filteredAnswer)
		}
	}
	// Join all lines with a newline character and add a newline at the end
	return strings.Join(answerLines, "\n") + "\n"
}
