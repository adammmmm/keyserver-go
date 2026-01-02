package main

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/adammmmm/go-junos"
	"github.com/antchfx/xmlquery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	RunError   = 0.0
	RunWarning = 0.5
	RunSuccess = 1.0
)

var (
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
	for i := 0; i < 31; i++ {
		bytes := make([]byte, 32)
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
		s.Template.ROLL = append(s.Template.ROLL, next.Format("2006-01-02.15:04:05"))
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
	// Local buffers instead of global
	var renderedTemplate bytes.Buffer
	var configCommands []string

	needsKey, usedKey, err := getKeychainStatus(s.Config)
	if err != nil {
		log.Error("keychain error", zap.Error(err))
		lastResult.Set(RunError)
		return err
	}

	if len(s.Config.Devices) != len(usedKey) {
		log.Error("keychain error", zap.Error(errors.New("didn't get a reply from all devices")))
		lastResult.Set(RunWarning)
		return errors.New("device response mismatch")
	}

	if !needsKey {
		lastResult.Set(RunSuccess)
		return nil
	}

	// Generate new keys
	s.UsedKey = usedKey[0]
	if err := s.Generate(); err != nil {
		log.Error("generation error", zap.Error(err))
		lastResult.Set(RunWarning)
		return err
	}

	// Prepare template
	funcMap := template.FuncMap{
		"inc": func(i int) int { return i + 1 },
	}

	tmpl, err := template.New("keychain.tmpl").Funcs(funcMap).ParseFS(embedTemplate, "*.tmpl")
	if err != nil {
		log.Error("template parse error", zap.Error(err))
		lastResult.Set(RunWarning)
		return err
	}

	if err := tmpl.Execute(&renderedTemplate, s); err != nil {
		log.Error("template execution error", zap.Error(err))
		lastResult.Set(RunWarning)
		return err
	}

	// Split into commands
	for _, line := range strings.Split(renderedTemplate.String(), "\n") {
		if len(strings.TrimSpace(line)) > 0 {
			configCommands = append(configCommands, line)
		}
	}

	// Update keychain safely
	if err := updateKeychain(s.Config, configCommands, log); err != nil {
		log.Error("update keychain error", zap.Error(err))
		lastResult.Set(RunError)
		return err
	}

	log.Info("keychain updated successfully")
	lastResult.Set(RunSuccess)
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

	byteValue, err := os.ReadFile(file)
	if err != nil {
		log.Error("couldn't open configuration file.")
		return config, err
	}

	if err := json.Unmarshal(byteValue, &config); err != nil {
		return config, err
	}

	return config, nil
}

func checkNTP(jnpr *junos.Junos) bool {
	output, err := jnpr.Command("show system uptime", "xml")
	if err != nil || output == "" {
		return false
	}

	doc, err := xmlquery.Parse(strings.NewReader(output))
	if err != nil {
		return false
	}

	ntp := xmlquery.FindOne(doc, "//system-uptime-information/time-source[contains(., 'NTP')]")
	return ntp != nil
}

func checkIfSame(ActiveIDs []int) bool {
	if len(ActiveIDs) <= 1 {
		return true
	}
	firstID := ActiveIDs[0]
	for _, id := range ActiveIDs {
		if id != firstID {
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
			return false, nil, fmt.Errorf("failed to connect to %s: %w", router, err)
		}

		// Ensure session closes after processing this router
		func() {
			defer jnpr.Close()

			// NTP check
			if config.NTP {
				if !checkNTP(jnpr) {
					err = fmt.Errorf("ntp mandatory but router %s does not have it configured", router)
					return
				}
			}

			// Get keychain info
			keychainOutput, cmdErr := jnpr.Command("show security keychain", "xml")
			if cmdErr != nil {
				err = fmt.Errorf("keychain command error on router %s: %w", router, cmdErr)
				return
			}

			doc, parseErr := xmlquery.Parse(strings.NewReader(keychainOutput))
			if parseErr != nil {
				err = fmt.Errorf("keychain parsing error on router %s: %w", router, parseErr)
				return
			}

			hakrPath := fmt.Sprintf("//hakr-keychain[hakr-keychain-name='%s']", config.Keychain)
			hakrInformation := xmlquery.FindOne(doc, hakrPath)
			if hakrInformation == nil {
				err = fmt.Errorf("couldn't get keychain info on router %s", router)
				return
			}

			ask := hakrInformation.SelectElement("hakr-keychain-active-send-key")
			ark := hakrInformation.SelectElement("hakr-keychain-active-receive-key")
			nsk := hakrInformation.SelectElement("hakr-keychain-next-send-key")
			nrk := hakrInformation.SelectElement("hakr-keychain-next-receive-key")
			nkt := hakrInformation.SelectElement("hakr-keychain-next-key-time")

			if ask == nil || ark == nil || nsk == nil || nrk == nil || nkt == nil {
				err = fmt.Errorf("missing key elements on router %s", router)
				return
			}

			askVal, arkVal := ask.InnerText(), ark.InnerText()
			if askVal != arkVal {
				err = fmt.Errorf("send (%s) and receive (%s) keys differ on %s", askVal, arkVal, router)
				return
			}

			askInt, convErr := strconv.Atoi(askVal)
			if convErr != nil {
				err = fmt.Errorf("cannot convert active key to int on router %s: %w", router, convErr)
				return
			}

			// Check if router is ready for new keys
			if nsk.InnerText() == "None" && nrk.InnerText() == "None" && nkt.InnerText() == "None" {
				ActiveIDs = append(ActiveIDs, askInt)
				readyForKeys = append(readyForKeys, router)
			} else {
				ActiveIDs = append(ActiveIDs, askInt)
			}
		}()

		if err != nil {
			return false, nil, err
		}
	}

	// Ensure all active IDs are the same
	if !checkIfSame(ActiveIDs) {
		return false, nil, errors.New("keychains unsynchronized across devices")
	}

	if len(readyForKeys) > 0 {
		if len(config.Devices) != len(readyForKeys) {
			return false, nil, errors.New("not all devices ready for new keys")
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

	// First, check commit locks on all devices
	for _, router := range config.Devices {
		jnpr, err := junos.NewSession(router+":22", auth)
		if err != nil {
			return err
		}

		log.Info("checking commit lock", zap.String("router", router))
		if err := jnpr.CommitCheck(); err != nil {
			jnpr.Close()
			if err.Error() == "expected element type <commit-results> but have <ok>" {
				continue
			}
			return err
		}
		jnpr.Close()
	}

	// Apply configuration to each device
	for _, router := range config.Devices {
		jnpr, err := junos.NewSession(router+":22", auth)
		if err != nil {
			return err
		}

		log.Info("applying keychain configuration", zap.String("router", router))
		if err := jnpr.Config(cmds, "set", true); err != nil {
			jnpr.Close()
			if err.Error() == "expected element type <commit-results> but have <ok>" {
				committed = append(committed, router)
				continue
			}

			if rollErr := rollbackCommitted(config, committed, log); rollErr != nil {
				return fmt.Errorf("config error: %v, rollback error: %v", err, rollErr)
			}
			return err
		}

		committed = append(committed, router)
		jnpr.Close()
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

		log.Info("rolling back configuration", zap.String("router", router))
		if err := jnpr.Rollback(1); err != nil {
			jnpr.Close()
			if err.Error() == "expected element type <commit-results> but have <ok>" {
				continue
			}
			return err
		}

		jnpr.Close()
	}

	return nil
}

func main() {
	log, _ := NewLogger()
	defer log.Sync()

	config, err := readConfig("config.json", log)
	if err != nil {
		log.Fatal("config issue")
	}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Info("listening on /metrics at :8799")
		http.ListenAndServe(":8799", nil)
	}()

	server := NewKeyServer(config)
	server.Run(log)
}
