package main

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"gopkg.in/ini.v1"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ProxyConfig represents the configuration for a proxy server
type ProxyConfig struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
}

// UpDNSConfig represents the configuration for an upstream DNS server
type UpDNSConfig struct {
	UpDNS string `json:"updns"`
}

// CacheEntry represents a single DNS cache entry
type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
}

// Cache represents a DNS cache with LRU eviction policy
type Cache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
}

type entry struct {
	key   string
	value CacheEntry
}

const (
	// MaxCacheEntries is the maximum number of cache entries per source IP
	MaxCacheEntries = 1000
)

// NewCache creates a new Cache
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*list.Element),
		lru:     list.New(),
	}
}

// Get retrieves a DNS response from the cache
func (c *Cache) Get(key string) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, found := c.entries[key]; found {
		c.lru.MoveToFront(el)
		return el.Value.(*entry).value.Msg, true
	}
	return nil, false
}

// Put adds a DNS response to the cache
func (c *Cache) Put(key string, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, found := c.entries[key]; found {
		c.lru.MoveToFront(el)
		el.Value.(*entry).value = CacheEntry{
			Msg:       msg,
			ExpiresAt: time.Now().Add(time.Duration(minTTL(msg)) * time.Second),
		}
	} else {
		if c.lru.Len() >= MaxCacheEntries {
			el := c.lru.Back()
			if el != nil {
				c.lru.Remove(el)
				delete(c.entries, el.Value.(*entry).key)
			}
		}
		c.entries[key] = c.lru.PushFront(&entry{
			key: key,
			value: CacheEntry{
				Msg:       msg,
				ExpiresAt: time.Now().Add(time.Duration(minTTL(msg)) * time.Second),
			},
		})
	}
}

// minTTL calculates the minimum TTL from a DNS message
func minTTL(msg *dns.Msg) uint32 {
	minTTL := ^uint32(0)
	for _, ans := range msg.Answer {
		if ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
		}
	}
	return minTTL
}

// Global variables
var (
	proxyConfigMap = make(map[string]ProxyConfig)
	cacheMap       = make(map[string]*Cache)
	upDNSMap       = make(map[string]UpDNSConfig)
	defaultUpDNS   = "8.8.8.8:53"
	configDnsMu    sync.RWMutex
	configProxyMu  sync.RWMutex
)

var log = logrus.New()

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
	// Join all lines with a newline character and add an additional newline at the end
	return strings.Join(answerLines, "\n") + "\n"
}

// queryTCP handles DNS queries over TCP
func queryTCP(domain string, dialer proxy.Dialer, upDNS string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	buf, err := msg.Pack()
	if err != nil {
		log.Errorf("Failed to pack DNS query: %v", err)
		return nil, err
	}

	// Prepend the length of the DNS query (2 bytes) for TCP transport
	tcpBuf := make([]byte, 2+len(buf))
	tcpBuf[0] = byte(len(buf) >> 8)
	tcpBuf[1] = byte(len(buf))
	copy(tcpBuf[2:], buf)

	// Create a unique connection for this query
	conn, err := dialer.Dial("tcp", upDNS)
	if err != nil {
		log.Errorf("Failed to dial to upstream DNS server: %v", err)
		return nil, err
	}
	defer conn.Close()

	// Send DNS query
	log.Debugf("Sending DNS query for domain: %s using protocol: tcp", domain)
	if _, err := conn.Write(tcpBuf); err != nil {
		log.Errorf("Failed to write to connection: %v", err)
		return nil, err
	}

	// Read DNS response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuf := make([]byte, 1024) // Increase buffer size for larger responses
	n, err := conn.Read(responseBuf)
	if err != nil {
		log.Errorf("Failed to read response: %v", err)
		if n > 0 {
			log.Warnf("Partial response received: %x", responseBuf[:n])
		}
		return nil, err
	}
	log.Debugf("Received response length: %d, data:%x", n, responseBuf[:n])

	// Remove the length prefix before unpacking the response
	response := new(dns.Msg)
	if err := response.Unpack(responseBuf[2:n]); err != nil {
		log.Errorf("Failed to unpack DNS response: %v", err)
		return nil, err
	}

	log.Infof("DNS query for domain: %s succeeded. Response: %v", domain, extractAnswerSection(response))

	return response, nil
}

// socks5UDPAssociate performs a UDP ASSOCIATE request to the SOCKS5 proxy
func socks5UDPAssociate(proxyAddr, username, password string) (*net.UDPConn, net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to proxy: %v", err)
	}
	log.Debugf("Connected to SOCKS5 proxy at %s", proxyAddr)

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
	log.Debugf("SOCKS5 handshake completed")

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
	log.Debugf("UDP ASSOCIATE request sent")

	response = make([]byte, 10)
	_, err = conn.Read(response)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to read UDP ASSOCIATE response: %v", err)
	}
	log.Debugf("UDP ASSOCIATE response received: %v", response)

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
	log.Debugf("Proxy UDP address: %v", proxyUDPAddr)

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
		log.Errorf("UDP ASSOCIATE failed: %v", err)
		return nil, err
	}
	defer udpConn.Close()
	// Close the TCP connection after UDP communication is done, The UDP communication
	// would be closed immediately by socks5 sever if the TCP connection is closed.
	defer tcpConn.Close()

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	buf, err := msg.Pack()
	if err != nil {
		log.Errorf("Failed to pack DNS query: %v", err)
		return nil, err
	}

	targetAddr, err := net.ResolveUDPAddr("udp", upDNS)
	if err != nil {
		log.Errorf("Failed to resolve target address: %v", err)
		return nil, err
	}
	log.Debugf("Resolved target address: %v", targetAddr)

	// Prepare the UDP packet
	var udpBuf bytes.Buffer
	udpBuf.WriteByte(0x00) // RSV
	udpBuf.WriteByte(0x00) // RSV
	udpBuf.WriteByte(0x00) // FRAG
	udpBuf.WriteByte(0x01) // ATYP (IPv4)
	udpBuf.Write(targetAddr.IP.To4())
	binary.Write(&udpBuf, binary.BigEndian, uint16(targetAddr.Port))
	udpBuf.Write(buf)

	log.Debugf("Constructed UDP packet data: %x", udpBuf.Bytes())

	// Send UDP packet to SOCKS5 proxy server
	log.Debugf("Sending UDP packet to proxy server")
	if _, err := udpConn.Write(udpBuf.Bytes()); err != nil {
		log.Errorf("Failed to send UDP data: %v", err)
		return nil, err
	}

	// Set read deadline
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Receive response
	responseBuf := make([]byte, 1024)
	n, addr, err := udpConn.ReadFrom(responseBuf)
	if err != nil {
		log.Errorf("Failed to read UDP response: %v", err)
		return nil, err
	}
	log.Debugf("Received UDP response from %v, data: %x", addr, responseBuf[:n])

	// Remove the SOCKS5 UDP header
	if n < 10 {
		return nil, fmt.Errorf("invalid UDP response length")
	}
	udpResponseData := responseBuf[10:n]

	// Unpack the response
	response := new(dns.Msg)
	if err := response.Unpack(udpResponseData); err != nil {
		log.Errorf("Failed to unpack DNS response: %v", err)
		log.Errorf("UDP response data: %x", udpResponseData)
		return nil, err
	}

	log.Infof("DNS query for domain: %s succeeded. Response: %v", domain, extractAnswerSection(response))

	return response, nil
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
			log.Errorf("Failed to create SOCKS5 dialer: %v", err)
			return nil, err
		}
		return queryTCP(domain, dialer, upDNS)
	} else if config.Protocol == "udp" {
		return queryUDP(domain, config, upDNS)
	}

	return nil, fmt.Errorf("Unsupported protocol: %s", config.Protocol)
}

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
		log.Infof("Cache hit for domain: %s from source IP: %s", domain, sourceIP)
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
	upstreamDNSConfig, exists := upDNSMap[sourceIP]
	if !exists {
		upstreamDNSConfig = UpDNSConfig{UpDNS: defaultUpDNS}
	}
	upDNS := upstreamDNSConfig.UpDNS
	configDnsMu.RUnlock()

	log.Debugf("Received DNS query for domain: %s from source IP: %s", domain, sourceIP)

	response, err := QueryDNS(domain, config, upDNS)
	if err != nil {
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		log.Errorf("DNS query for domain: %s failed: %v", domain, err)
		return
	}

	// Update cache
	cache.Put(domain, response)

	m.Answer = response.Answer
	log.Debugf("Writing DNS response for domain: %s", domain)
	if err := w.WriteMsg(m); err != nil {
		log.Errorf("Failed to write DNS response: %v", err)
	}
}

// UpdateProxyConfig updates the proxy configuration
func UpdateProxyConfig(c *gin.Context) {
	var newConfig map[string]ProxyConfig
	if err := c.ShouldBindJSON(&newConfig); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	configProxyMu.Lock()
	defer configProxyMu.Unlock()
	for ip, config := range newConfig {
		proxyConfigMap[ip] = config
	}

	c.JSON(200, gin.H{"status": "Proxy configuration updated"})
}

// UpdateUpDNSConfig updates the upstream DNS configuration for specific source IPs
func UpdateUpDNSConfig(c *gin.Context) {
	var newConfig map[string]UpDNSConfig
	if err := c.ShouldBindJSON(&newConfig); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	configDnsMu.Lock()
	for ip, dnsConfig := range newConfig {
		upDNSMap[ip] = dnsConfig
	}
	configDnsMu.Unlock()

	c.JSON(200, gin.H{"status": "Upstream DNS configuration updated"})
}

type ProxyFileConfig struct {
	Server   string
	Port     int
	Username string
	Password string
	Protocol string
}

type LanFileConfig struct {
	IP          string
	UpDNS       string
	ProxyConfig ProxyFileConfig
}

type FileConfig struct {
	ProxyServer ProxyFileConfig
	LanConfig   LanFileConfig
}

func loadConfig(file string) (*FileConfig, error) {
	cfg, err := ini.Load(file)
	if err != nil {
		return nil, err
	}

	config := &FileConfig{}
	err = cfg.Section("ProxyServer").MapTo(&config.ProxyServer)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func main() {
	// Set Gin mode to release
	gin.SetMode(gin.ReleaseMode)

	// Set logrus to log to stdout and set log level to Info
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)

	config, err := loadConfig("config.ini")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
		return
	}
	// Initialize default proxy and upstream DNS configuration
	proxyConfigMap["default"] = ProxyConfig{
		Server:   config.ProxyServer.Server,
		Port:     config.ProxyServer.Port,
		Username: config.ProxyServer.Username,
		Password: config.ProxyServer.Password,
		Protocol: config.ProxyServer.Protocol,
	}
	upDNSMap["default"] = UpDNSConfig{UpDNS: defaultUpDNS}

	// Initialize proxy and upstream DNS configuration for specific IP range
	for i := 2; i <= 30; i++ {
		ip := "172.18.1." + strconv.Itoa(i)
		proxyConfigMap[ip] = proxyConfigMap["default"]
		cacheMap[ip] = NewCache()
		upDNSMap[ip] = upDNSMap["default"]
	}

	// Create DNS server
	dns.HandleFunc(".", DNSHandler)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
	}()
	defer server.Shutdown()

	// Create HTTP server for updating proxy and upstream DNS configurations
	router := gin.Default()
	router.POST("/update-proxy", UpdateProxyConfig)
	router.POST("/update-dns", UpdateUpDNSConfig)

	// Start HTTP server
	go func() {
		if err := router.Run(":8080"); err != nil {
			log.Fatalf("Failed to run HTTP server: %v", err)
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down servers...")
}
