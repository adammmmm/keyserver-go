package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/antchfx/xmlquery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/scottdware/go-junos"
	"go.uber.org/zap"
)

var (
	renderedTemplate bytes.Buffer
	configCommands   []string
	lastResult       = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "keychain_result",
		Help: "Keychain run result (0 = error, 0.5 = warning, 1 = noop or success",
	})
)

type Config struct {
	User     string   `json:"user"`
	Key      string   `json:"key"`
	Interval int      `json:"interval"`
	Keychain string   `json:"keychain"`
	NTP      bool     `json:"ntp"`
	Devices  []string `json:"devices"`
}

type KeyServer struct {
	UsedKey  int
	Config   Config
	Template Template
}

type Template struct {
	CKN  []string
	CAK  []string
	ROLL []string
}

func NewKeyServer(config Config) *KeyServer {
	return &KeyServer{
		Config: config,
		Template: Template{
			CAK:  []string{},
			CKN:  []string{},
			ROLL: []string{},
		},
	}
}

func (s *KeyServer) Generate() error {
	for i := 0; i < 31; i++ {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return err
		}
		s.Template.CAK = append(s.Template.CAK, hex.EncodeToString(bytes))
	}
	for y := 0; y < 31; y++ {
		bytes := make([]byte, 31)
		if _, err := rand.Read(bytes); err != nil {
			return err
		}
		s.Template.CKN = append(s.Template.CKN, hex.EncodeToString(bytes))
	}
	for z := 0; z < 31; z++ {
		initial := time.Now().Add(time.Hour * time.Duration(s.Config.Interval))
		next := initial.Add((time.Hour * time.Duration(z)) * time.Duration(s.Config.Interval))
		timeString := next.Format("2006-01-02.15:04:05")
		s.Template.ROLL = append(s.Template.ROLL, timeString)
	}
	return nil
}

func NewLogger() (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{
		"keyserver.log",
		"stderr",
	}
	return cfg.Build()
}

func readConfig(file string, log *zap.Logger) (Config, error) {
	var config Config
	jsonFile, err := os.Open(file)
	if err != nil {
		log.Error("couldn't open configuration file.")
		return config, err
	}
	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &config)
	return config, nil
}

func checkNTP(jnpr *junos.Junos) bool {
	output, err := jnpr.Command("show system uptime", "xml")
	if err != nil {
		return false
	}
	doc, err := xmlquery.Parse(strings.NewReader(output))
	if err != nil {
		return false
	}

	uptimeInformation := xmlquery.FindOne(doc, "//system-uptime-information")
	if ntp := uptimeInformation.SelectElement("time-source"); ntp != nil {
		if !strings.Contains(ntp.InnerText(), "NTP") {
			return false
		}
	}

	return true
}

func checkIfSame(ActiveIDs []int) bool {
	for i := 0; i < len(ActiveIDs); i++ {
		if ActiveIDs[i] != ActiveIDs[0] {
			return false
		}
	}
	return true
}

func getKeychainStatus(config Config) (bool, []int, error) {
	var ActiveIDs []int
	var readyForKeys []string
	auth := &junos.AuthMethod{
		Username:   config.User,
		PrivateKey: config.Key,
	}
	for _, router := range config.Devices {
		jnpr, err := junos.NewSession(router+":22", auth)
		if err != nil {
			return false, []int{}, err
		}
		defer jnpr.Close()

		if config.NTP {
			ok := checkNTP(jnpr)
			if !ok {
				return false, []int{}, errors.New("ntp mandatory but router doesn't have it configured")
			}
		}

		keychainOutput, err := jnpr.Command("show security keychain", "xml")
		if err != nil {
			return false, []int{}, errors.New("keychain error")
		}
		doc, err := xmlquery.Parse(strings.NewReader(keychainOutput))
		if err != nil {
			return false, []int{}, errors.New("keychain error")
		}
		hakrKeychain := fmt.Sprintf("//hakr-keychain[hakr-keychain-name='%s']", config.Keychain)
		hakrInformation := xmlquery.FindOne(doc, hakrKeychain)
		if hakrInformation == nil {
			return false, []int{}, errors.New("couldn't get keychain information")
		}
		activeSendKey := hakrInformation.SelectElement("hakr-keychain-active-send-key")
		if activeSendKey == nil {
			return false, []int{}, errors.New("keychain active send key error")
		}
		activeReceiveKey := hakrInformation.SelectElement("hakr-keychain-active-receive-key")
		if activeReceiveKey == nil {
			return false, []int{}, errors.New("keychain active receive key error")
		}
		nextSendKey := hakrInformation.SelectElement("hakr-keychain-next-send-key")
		if nextSendKey == nil {
			return false, []int{}, errors.New("keychain next send key error")
		}
		nextReceiveKey := hakrInformation.SelectElement("hakr-keychain-next-receive-key")
		if nextReceiveKey == nil {
			return false, []int{}, errors.New("keychain next receive key error")
		}
		nextKeyTime := hakrInformation.SelectElement("hakr-keychain-next-key-time")
		if nextKeyTime == nil {
			return false, []int{}, errors.New("keychain next key time error")
		}
		ask := activeSendKey.InnerText()
		ark := activeReceiveKey.InnerText()
		nsk := nextSendKey.InnerText()
		nrk := nextReceiveKey.InnerText()
		nkt := nextKeyTime.InnerText()
		if ask == ark {
			askInt, err := strconv.Atoi(ask)
			if err != nil {
				return false, []int{}, errors.New("string conversion error")
			}
			if nsk == "None" && nrk == "None" && nkt == "None" {
				ActiveIDs = append(ActiveIDs, askInt)
				readyForKeys = append(readyForKeys, router)
			} else {
				ActiveIDs = append(ActiveIDs, askInt)
			}
		} else {
			return false, []int{}, errors.New("differing send and receive keys")
		}
	}
	sameKeys := checkIfSame(ActiveIDs)
	if !sameKeys {
		return false, []int{}, errors.New("keychains unsynchronized")
	}
	if len(readyForKeys) > 0 {
		if len(config.Devices) != len(readyForKeys) {
			return false, []int{}, errors.New("keychains unsynchronized")
		}
		return true, ActiveIDs, nil
	}
	return false, ActiveIDs, nil
}

func updateKeychain(config Config, cmds []string) error {
	auth := &junos.AuthMethod{
		Username:   config.User,
		PrivateKey: config.Key,
	}
	for _, router := range config.Devices {
		jnpr, err := junos.NewSession(router+":22", auth)
		if err != nil {
			return err
		}
		defer jnpr.Close()
		if err := jnpr.Config(cmds, "set", true); err != nil {
			if err.Error() == "expected element type <commit-results> but have <ok>" {
				continue
			}
			return err
		}
	}
	return nil
}

func main() {
	log, _ := NewLogger()
	defer log.Sync()
	config, err := readConfig("config.json", log)
	if err != nil {
		log.Error("config issue")
	}
	log.Debug("config",
		zap.String("user:", config.User),
		zap.String("key:", config.Key),
		zap.Int("interval:", config.Interval),
		zap.String("keychain:", config.Keychain),
		zap.Bool("ntp:", config.NTP),
		zap.Strings("devices:", config.Devices),
	)
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Info("listening on /metrics at :8799")
		http.ListenAndServe(":8799", nil)
	}()
	for {
		needsKey, usedKey, err := getKeychainStatus(config)
		if err != nil {
			log.Error("keychain error", zap.Error(err))
			lastResult.Set(0.0)
			continue
		}
		if len(config.Devices) != len(usedKey) {
			log.Error("keychain error", zap.Error(errors.New("didn't get a reply from all devices")))
			lastResult.Set(0.5)
			continue
		}
		if needsKey {
			server := NewKeyServer(config)
			server.UsedKey = usedKey[0]
			if err := server.Generate(); err != nil {
				log.Error("generation error", zap.Error(err))
				lastResult.Set(0.5)
				continue
			}

			funcMap := template.FuncMap{
				"inc": func(i int) int {
					return i + 1
				},
			}
			t, err := template.New("keychain.tmpl").Funcs(funcMap).ParseFiles("keychain.tmpl")
			if err != nil {
				log.Error("template error", zap.Error(err))
				lastResult.Set(0.5)
				continue
			}
			executionErr := t.Execute(&renderedTemplate, server)
			if executionErr != nil {
				log.Error("template execution error", zap.Error(executionErr))
				lastResult.Set(0.5)
				continue
			}
			templateString := renderedTemplate.String()
			rawCfgCommands := strings.Split(templateString, "\n")
			for _, value := range rawCfgCommands {
				if len(value) > 1 {
					configCommands = append(configCommands, value)
				}
			}
			if err := updateKeychain(config, configCommands); err != nil {
				log.Error("update keychain error", zap.Error(err))
				lastResult.Set(0.0)
				continue
			}
			log.Info("updated keychain")
			lastResult.Set(1.0)
		} else {
			lastResult.Set(1.0)
			log.Info("no action needed")
		}
		time.Sleep(time.Hour * 24)
	}
}
