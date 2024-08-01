package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/urfave/cli"
	"os"
	"strings"
)

/**
 * @Author: gedebin
 * @Date: 2024/8/1 09:40
 * @Desc:
 */

var modelType = map[string]string{
	"debug":   gin.DebugMode,
	"release": gin.ReleaseMode,
	"test":    gin.TestMode,
}

var logLevel = map[string]logrus.Level{
	"trace": logrus.TraceLevel,
	"debug": logrus.DebugLevel,
	"info":  logrus.InfoLevel,
	"warn":  logrus.WarnLevel,
	"error": logrus.ErrorLevel,
}

var Config *struct {
	LogConfig    LogConfig    `mapstructure:"log" json:"log" yaml:"log"`
	Model        string       `mapstructure:"model" json:"model" yaml:"model"`
	DNSPort      string       `mapstructure:"dns_port" json:"dns_port" yaml:"dns_port"`
	ApiPort      string       `mapstructure:"api_port" json:"api_port" yaml:"api_port"`
	ProxyDefault ProxyDefault `mapstructure:"proxy_default" json:"proxy_default" yaml:"proxy_default"`
}

type LogConfig struct {
	OutPut string `mapstructure:"output" json:"output" yaml:"output"`
	File   string `mapstructure:"file" json:"file" yaml:"file"`
	Level  string `mapstructure:"level" json:"level" yaml:"level"`
}
type ProxyDefault struct {
	Server   string `mapstructure:"server" json:"server" yaml:"server"`
	Port     int    `mapstructure:"port" json:"port" yaml:"port"`
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
	Protocol string `mapstructure:"protocol" json:"protocol" yaml:"protocol"`
	Upstream string `mapstructure:"upstream" json:"upstream" yaml:"upstream"`
}

func InitService(c *cli.Context) error {

	// 初始化配置文件
	err := InitConfig(c.String("c"))
	if err != nil {
		panic(err)
	}

	// Set Gin mode to release
	gin.SetMode(modelType[Config.Model])

	// 初始化日志
	InitLog(&Config.LogConfig)

	return nil
}

func InitConfig(configURL string) (err error) {
	// 初始化配置文件代码
	// 使用viper包加载配置文件config.yml
	v := viper.New()
	v.SetConfigFile(configURL)
	err = v.ReadInConfig()
	if err != nil {
		err = fmt.Errorf("fatal error config file: %w", err)
		return
	}
	if err = v.Unmarshal(&Config); err != nil {
		return err
	}
	return
}

func InitLog(logConfig *LogConfig) {
	// 设置日志格式为json格式
	formatter := &logrus.JSONFormatter{
		//DisableTimestamp: true,
	}
	logrus.SetFormatter(formatter)

	logrus.SetLevel(logLevel[logConfig.Level])

	if strings.ToLower(logConfig.OutPut) == "stdout" {
		// debug模式输出到终端
		logrus.Info("start log successfully")
		logrus.SetOutput(os.Stdout)
	} else {
		// 否则输出到文件中
		file, err := os.OpenFile(logConfig.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			// 打开文件失败，将错误信息输出到终端
			logrus.Error("open file error: ", err)
			logrus.SetOutput(os.Stdout)
		} else {
			logrus.SetOutput(file)
			logrus.Info("open file success,starting with log")
		}
	}
}
