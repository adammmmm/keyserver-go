package main

import (
	"bytes"
	"crypto/rand"
	"embed"
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
	//go:embed keychain.tmpl
	embedTemplate embed.FS
	lastResult    = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "keyserver_result",
		Help: "Keyserver run result (0 = error, 0.5 = warning, 1 = noop or success)",
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
	bytes := make([]byte, 32)
	for i := 0; i < 31; i++ {
		if _, err := rand.Read(bytes); err != nil {
			return err
		}
		s.Template.CAK = append(s.Template.CAK, hex.EncodeToString(bytes))

		if _, err := rand.Read(bytes); err != nil {
			return err
		}
		s.Template.CKN = append(s.Template.CKN, hex.EncodeToString(bytes))

		initial := time.Now().Add(time.Hour * time.Duration(s.Config.Interval))
		next := initial.Add((time.Hour * time.Duration(i)) * time.Duration(s.Config.Interval))
		timeString := next.Format("2006-01-02.15:04:05")
		s.Template.ROLL = append(s.Template.ROLL, timeString)
	}
	return nil
}

func (s *KeyServer) Run(log *zap.Logger) {
	for {
		if err := s.loop(log); err != nil {
			log.Error("loop error", zap.Error(err))
		}
		time.Sleep(time.Hour * 24)
	}
}

func (s *KeyServer) loop(log *zap.Logger) error {
	needsKey, usedKey, err := getKeychainStatus(s.Config)
	if err != nil {
		log.Error("keychain error", zap.Error(err))
		lastResult.Set(0.0)
		return err
	}

	if len(s.Config.Devices) != len(usedKey) {
		log.Error("keychain error", zap.Error(errors.New("didn't get a reply from all devices")))
		lastResult.Set(0.5)
		return err
	}

	if needsKey {
		s.UsedKey = usedKey[0]
		if err := s.Generate(); err != nil {
			log.Error("generation error", zap.Error(err))
			lastResult.Set(0.5)
			return err
		}

		funcMap := template.FuncMap{
			"inc": func(i int) int {
				return i + 1
			},
		}

		t, err := template.New("keychain.tmpl").Funcs(funcMap).ParseFS(embedTemplate, "*.tmpl")
		if err != nil {
			log.Error("template error", zap.Error(err))
			lastResult.Set(0.5)
			return err
		}

		executionErr := t.Execute(&renderedTemplate, s)
		if executionErr != nil {
			log.Error("template execution error", zap.Error(executionErr))
			lastResult.Set(0.5)
			return err
		}

		templateString := renderedTemplate.String()
		rawCfgCommands := strings.Split(templateString, "\n")
		for _, value := range rawCfgCommands {
			if len(value) > 1 {
				configCommands = append(configCommands, value)
			}
		}

		if err := updateKeychain(s.Config, configCommands, log); err != nil {
			log.Error("update keychain error", zap.Error(err))
			lastResult.Set(0.0)
			return err
		}

		log.Info("updated keychain")
		lastResult.Set(1.0)
		return nil
	}

	lastResult.Set(1.0)
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
				errMsg := fmt.Sprintf("ntp mandatory but router %s does not have it configured", router)
				return false, []int{}, errors.New(errMsg)
			}
		}

		keychainOutput, err := jnpr.Command("show security keychain", "xml")
		if err != nil {
			errMsg := fmt.Sprintf("keychain op command error on router %s", router)
			return false, []int{}, errors.New(errMsg)
		}
		doc, err := xmlquery.Parse(strings.NewReader(keychainOutput))
		if err != nil {
			errMsg := fmt.Sprintf("keychain parsing error on router %s", router)
			return false, []int{}, errors.New(errMsg)
		}

		hakrKeychain := fmt.Sprintf("//hakr-keychain[hakr-keychain-name='%s']", config.Keychain)
		hakrInformation := xmlquery.FindOne(doc, hakrKeychain)

		if hakrInformation == nil {
			errMsg := fmt.Sprintf("couldn't get keychain information on router %s", router)
			return false, []int{}, errors.New(errMsg)
		}
		activeSendKey := hakrInformation.SelectElement("hakr-keychain-active-send-key")
		if activeSendKey == nil {
			errMsg := fmt.Sprintf("couldn't get active send key from router %s", router)
			return false, []int{}, errors.New(errMsg)
		}
		activeReceiveKey := hakrInformation.SelectElement("hakr-keychain-active-receive-key")
		if activeReceiveKey == nil {
			errMsg := fmt.Sprintf("couldn't get active receive key from router %s", router)
			return false, []int{}, errors.New(errMsg)
		}
		nextSendKey := hakrInformation.SelectElement("hakr-keychain-next-send-key")
		if nextSendKey == nil {
			errMsg := fmt.Sprintf("couldn't get next send key from router %s", router)
			return false, []int{}, errors.New(errMsg)
		}
		nextReceiveKey := hakrInformation.SelectElement("hakr-keychain-next-receive-key")
		if nextReceiveKey == nil {
			errMsg := fmt.Sprintf("couldn't get next receive key from router %s", router)
			return false, []int{}, errors.New(errMsg)
		}
		nextKeyTime := hakrInformation.SelectElement("hakr-keychain-next-key-time")
		if nextKeyTime == nil {
			errMsg := fmt.Sprintf("couldn't get next key time from router %s", router)
			return false, []int{}, errors.New(errMsg)
		}

		ask := activeSendKey.InnerText()
		ark := activeReceiveKey.InnerText()
		nsk := nextSendKey.InnerText()
		nrk := nextReceiveKey.InnerText()
		nkt := nextKeyTime.InnerText()

		if ask == ark {
			askInt, err := strconv.Atoi(ask)
			if err != nil {
				errMsg := fmt.Sprintf("string conversion error of %s on router %s", ask, router)
				return false, []int{}, errors.New(errMsg)
			}
			if nsk == "None" && nrk == "None" && nkt == "None" {
				ActiveIDs = append(ActiveIDs, askInt)
				readyForKeys = append(readyForKeys, router)
			} else {
				ActiveIDs = append(ActiveIDs, askInt)
			}
		} else {
			errMsg := fmt.Sprintf("differing send (%s) and receive (%s) keys on %s", ask, nsk, router)
			return false, []int{}, errors.New(errMsg)
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

func updateKeychain(config Config, cmds []string, log *zap.Logger) error {
	var committed []string

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

		log.Info("keychain update check lock", zap.String("router:", router))
		if err := jnpr.CommitCheck(); err != nil {
			if err.Error() == "expected element type <commit-results> but have <ok>" {
				continue
			}
			return err
		}
	}

	for _, router := range config.Devices {
		jnpr, err := junos.NewSession(router+":22", auth)
		if err != nil {
			return err
		}
		defer jnpr.Close()

		log.Info("keychain update config", zap.String("router:", router))
		if err := jnpr.Config(cmds, "set", true); err != nil {
			if err.Error() == "expected element type <commit-results> but have <ok>" {
				committed = append(committed, router)
				continue
			}
			if rollErr := rollbackCommitted(config, committed, log); rollErr != nil {
				return err
			}
			return err
		}
		committed = append(committed, router)
	}

	return nil
}

func rollbackCommitted(config Config, routers []string, log *zap.Logger) error {
	auth := &junos.AuthMethod{
		Username:   config.User,
		PrivateKey: config.Key,
	}

	for _, router := range routers {
		jnpr, err := junos.NewSession(router+":22", auth)
		if err != nil {
			return err
		}
		defer jnpr.Close()

		log.Info("rollback config", zap.String("router:", router))
		if err := jnpr.Rollback(1); err != nil {
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

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Info("listening on /metrics at :8799")
		http.ListenAndServe(":8799", nil)
	}()

	server := NewKeyServer(config)
	server.Run(log)
}
