package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
)

/**
 * @Author: gedebin
 * @Date: 2024/8/1 10:56
 * @Desc:
 */

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
		// Validate the new proxy configurations
		if config.Server == "" || config.Port == 0 || config.Protocol == "" {
			c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid proxy configuration for IP %s", ip)})
			return
		}
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
		// Validate the new upstream DNS configurations
		if dnsConfig.UpDNS == "" {
			c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid upstream DNS configuration for IP %s", ip)})
			return
		}

		// Check if UpDNS has a valid format (e.g., "8.8.8.8:53")
		if _, _, err := net.SplitHostPort(dnsConfig.UpDNS); err != nil {
			c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid upstream DNS format for IP %s: %v", ip, err)})
			return
		}
		upstreamDNSMap[ip] = dnsConfig
	}
	configDnsMu.Unlock()

	c.JSON(200, gin.H{"status": "Upstream DNS configuration updated"})
}
