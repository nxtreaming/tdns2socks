package main

import (
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"os/signal"
	"syscall"
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
	// ip:port, port is 53(Legacy Over UDP/TCP), 853(DoT over TCP), 443(HTTPS over TCP)
	UpDNS string `json:"updns"`
}

// Global variables
var (
	proxyConfigMap = make(map[string]ProxyConfig)
	upstreamDNSMap = make(map[string]UpDNSConfig)
)

func main() {
	app := cli.NewApp()
	app.Name = "tdns2socks"
	app.Usage = "run scripts!"
	app.Version = "1.0.0"
	app.Author = "anonymous"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "c",
			Value: "./config.yaml",
			Usage: "config file url",
		},
	}
	app.Before = InitService

	app.Action = func(c *cli.Context) {
		println("Run Server.")
		// Initialize default proxy and upstream DNS configuration
		proxyConfigMap["default"] = ProxyConfig{
			Server:   Config.ProxyDefault.Server,
			Port:     Config.ProxyDefault.Port,
			Username: Config.ProxyDefault.Username,
			Password: Config.ProxyDefault.Password,
			Protocol: Config.ProxyDefault.Protocol,
		}
		upstreamDNSMap["default"] = UpDNSConfig{UpDNS: Config.ProxyDefault.Upstream}

		// Create DNS server
		dns.HandleFunc(".", DNSHandler)
		server := &dns.Server{Addr: ":" + Config.DNSPort, Net: "udp"}
		go func() {
			if err := server.ListenAndServe(); err != nil {
				logrus.Fatalf("Failed to start DNS server: %v", err)
			}
		}()
		defer server.Shutdown()

		// Create HTTP server for updating proxy and upstream DNS configurations
		ginEngine := gin.New()
		ginEngine.Use(gin.Logger())

		ginEngine.Use(func(c *gin.Context) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204) // OPTIONS 请求直接返回 204 状态码
				return
			}
			c.Next()
		})
		ginEngine.POST("/update-proxy", UpdateProxyConfig)
		ginEngine.POST("/update-dns", UpdateUpDNSConfig)

		// Start HTTP server
		go func() {
			if err := ginEngine.Run(":" + Config.ApiPort); err != nil {
				logrus.Fatalf("Failed to run HTTP server: %v", err)
			}
		}()

		// Handle graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		for _, cache := range cacheMap {
			cache.mu.Lock()
			for key, timer := range cache.timers {
				timer.Stop()
				delete(cache.timers, key)
			}
			cache.mu.Unlock()
		}
		logrus.Println("Shutting down servers...")

	}
	err := app.Run(os.Args)
	if err != nil {
		panic("app run error:" + err.Error())
	}

}
