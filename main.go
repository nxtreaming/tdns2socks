package main

import (
	"container/list"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
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

func extractAnswerSection(response *dns.Msg) string {
	if response == nil {
		return ""
	}

	var answerSection string
	for _, ans := range response.Answer {
		answerSection += ans.String() + "\n"
	}
	return answerSection
}

// QueryDNS queries DNS through a SOCKS5 proxy using the specified protocol (TCP or UDP)
func QueryDNS(domain string, config ProxyConfig, upDNS string) (*dns.Msg, error) {
	// Create a SOCKS5 dialer
	proxyAddr := net.JoinHostPort(config.Server, strconv.Itoa(config.Port))
	auth := &proxy.Auth{
		User:     config.Username,
		Password: config.Password,
	}
	dialer, err := proxy.SOCKS5(config.Protocol, proxyAddr, auth, proxy.Direct)
	if err != nil {
		log.Printf("Failed to create SOCKS5 dialer: %v", err)
		return nil, err
	}

	// Create DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	buf, err := msg.Pack()
	if err != nil {
		log.Printf("Failed to pack DNS query: %v", err)
		return nil, err
	}

	// Prepend the length of the DNS query (2 bytes) for TCP transport
	tcpBuf := make([]byte, 2+len(buf))
	tcpBuf[0] = byte(len(buf) >> 8)
	tcpBuf[1] = byte(len(buf))
	copy(tcpBuf[2:], buf)

	// Log the packed DNS query
	log.Printf("Packed DNS query (with length): %x", tcpBuf)

	// Create a unique connection for this query
	conn, err := dialer.Dial(config.Protocol, upDNS)
	if err != nil {
		log.Printf("Failed to dial to upstream DNS server: %v", err)
		return nil, err
	}
	defer conn.Close()

	// Send DNS query
	log.Printf("Sending DNS query for domain: %s using protocol: %s", domain, config.Protocol)
	if _, err := conn.Write(tcpBuf); err != nil {
		log.Printf("Failed to write to connection: %v", err)
		return nil, err
	}

	// Read DNS response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	responseBuf := make([]byte, 1024) // Increase buffer size for larger responses
	n, err := conn.Read(responseBuf)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		if n > 0 {
			log.Printf("Partial response received: %x", responseBuf[:n])
		}
		return nil, err
	}
	log.Printf("Received response length: %d", n)
	log.Printf("Received response data: %x", responseBuf[:n])

	// Remove the length prefix before unpacking the response
	response := new(dns.Msg)
	if err := response.Unpack(responseBuf[2:n]); err != nil {
		log.Printf("Failed to unpack DNS response: %v", err)
		return nil, err
	}

	log.Printf("DNS query for domain: %s succeeded. Response: %v", domain, extractAnswerSection(response))

	return response, nil
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
		log.Printf("Cache hit for domain: %s from source IP: %s\n", domain, sourceIP)
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

	log.Printf("Received DNS query for domain: %s from source IP: %s", domain, sourceIP)

	response, err := QueryDNS(domain, config, upDNS)
	if err != nil {
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		log.Printf("DNS query for domain: %s failed: %v", domain, err)
		return
	}

	// Update cache
	cache.Put(domain, response)

	m.Answer = response.Answer
	log.Printf("Writing DNS response for domain: %s", domain)
	if err := w.WriteMsg(m); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
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

func main() {
	// Set Gin mode to release
	gin.SetMode(gin.ReleaseMode)

	// Initialize default proxy and upstream DNS configuration
	proxyConfigMap["default"] = ProxyConfig{
		Server:   "default.proxy.server",
		Port:     1080,
		Username: "defaultUsername",
		Password: "defaultPassword",
		Protocol: "tcp", // Default use: TCP
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
