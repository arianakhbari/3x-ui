import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"x-ui/logger"
	"x-ui/xray"

	"go.uber.org/atomic"
)

var (
	p                 *xray.Process
	lock              sync.Mutex
	isNeedXrayRestart atomic.Bool
	result            string
)

type XrayService struct {
	inboundService InboundService
	settingService SettingService
	xrayAPI        xray.XrayAPI
	// Add a channel to signal process termination
	stopChan chan struct{}
}

// Initialize the stop channel when creating a new XrayService
func NewXrayService(inboundService InboundService, settingService SettingService, xrayAPI xray.XrayAPI) *XrayService {
	return &XrayService{
		inboundService: inboundService,
		settingService: settingService,
		xrayAPI:        xrayAPI,
		stopChan:       make(chan struct{}),
	}
}

func (s *XrayService) IsXrayRunning() bool {
	return p != nil && p.IsRunning()
}

func (s *XrayService) GetXrayErr() error {
	if p == nil {
		return nil
	}
	return p.GetErr()
}

func (s *XrayService) GetXrayResult() string {
	if result != "" {
		return result
	}
	if s.IsXrayRunning() {
		return ""
	}
	if p == nil {
		return ""
	}
	result = p.GetResult()
	return result
}

func (s *XrayService) GetXrayVersion() string {
	if p == nil {
		return "Unknown"
	}
	return p.GetVersion()
}

func RemoveIndex(s []interface{}, index int) []interface{} {
	return append(s[:index], s[index+1:]...)
}

func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}

	// Removed redundant call to AddTraffic
	// s.inboundService.AddTraffic(nil, nil)

	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		// get settings clients
		settings := map[string]interface{}{}
		err := json.Unmarshal([]byte(inbound.Settings), &settings)
		if err != nil {
			logger.Errorf("Failed to unmarshal inbound settings: %v", err)
			continue
		}
		clients, ok := settings["clients"].([]interface{})
		if ok {
			// check users active or not
			clientStats := inbound.ClientStats
			indexDecrease := 0 // Moved outside the loop
			for _, clientTraffic := range clientStats {
				for index, client := range clients {
					c := client.(map[string]interface{})
					if c["email"] == clientTraffic.Email {
						if !clientTraffic.Enable {
							clients = RemoveIndex(clients, index-indexDecrease)
							indexDecrease++
							logger.Infof("Remove Inbound User %s due to expiration or traffic limit", c["email"])
						}
					}
				}
			}

			// clear client config for additional parameters
			var final_clients []interface{}
			for _, client := range clients {
				c := client.(map[string]interface{})
				if c["enable"] != nil {
					if enable, ok := c["enable"].(bool); ok && !enable {
						continue
					}
				}
				// Retain necessary keys and remove others
				for key := range c {
					if key != "email" && key != "id" && key != "password" && key != "flow" && key != "method" {
						delete(c, key)
					}
				}
				if c["flow"] == "xtls-rprx-vision-udp443" {
					c["flow"] = "xtls-rprx-vision"
				}
				final_clients = append(final_clients, interface{}(c))
			}

			settings["clients"] = final_clients
			modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return nil, err
			}

			inbound.Settings = string(modifiedSettings)
		}

		if len(inbound.StreamSettings) > 0 {
			// Unmarshal stream JSON
			var stream map[string]interface{}
			err := json.Unmarshal([]byte(inbound.StreamSettings), &stream)
			if err != nil {
				logger.Errorf("Failed to unmarshal stream settings: %v", err)
				continue
			}

			// Remove the "settings" field under "tlsSettings" and "realitySettings"
			if tlsSettings, ok := stream["tlsSettings"].(map[string]interface{}); ok {
				delete(tlsSettings, "settings")
			}
			if realitySettings, ok := stream["realitySettings"].(map[string]interface{}); ok {
				delete(realitySettings, "settings")
			}

			delete(stream, "externalProxy")

			newStream, err := json.MarshalIndent(stream, "", "  ")
			if err != nil {
				return nil, err
			}
			inbound.StreamSettings = string(newStream)
		}

		inboundConfig := inbound.GenXrayInboundConfig()
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
	}
	return xrayConfig, nil
}

func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	if !s.IsXrayRunning() {
		err := errors.New("xray is not running")
		logger.Debug("Attempted to fetch Xray traffic, but Xray is not running:", err)
		return nil, nil, err
	}
	apiPort := p.GetAPIPort()
	s.xrayAPI.Init(apiPort)
	// Removed defer s.xrayAPI.Close() to prevent premature closure

	traffic, clientTraffic, err := s.xrayAPI.GetTraffic(true)
	if err != nil {
		logger.Debug("Failed to fetch Xray traffic:", err)
		return nil, nil, err
	}
	return traffic, clientTraffic, nil
}

// Added a monitor function to restart Xray on unexpected termination
func (s *XrayService) monitorXrayProcess() {
	for {
		select {
		case <-s.stopChan:
			logger.Debug("Xray process monitor stopped.")
			return
		default:
			if !s.IsXrayRunning() {
				logger.Warn("Xray process has stopped unexpectedly. Restarting...")
				err := s.RestartXray(true)
				if err != nil {
					logger.Errorf("Failed to restart Xray: %v", err)
				}
			}
			time.Sleep(5 * time.Second) // Adjust the interval as needed
		}
	}
}

func (s *XrayService) RestartXray(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("Restarting Xray, force:", isForce)

	xrayConfig, err := s.GetXrayConfig()
	if err != nil {
		return err
	}

	if s.IsXrayRunning() {
		if !isForce && p.GetConfig().Equals(xrayConfig) {
			logger.Debug("No need to restart Xray; configuration unchanged.")
			return nil
		}
		err := p.Stop()
		if err != nil {
			logger.Errorf("Error stopping Xray: %v", err)
		}
	}

	p = xray.NewProcess(xrayConfig)
	result = ""
	err = p.Start()
	if err != nil {
		logger.Errorf("Error starting Xray: %v", err)
		return err
	}

	// Start the monitor in a separate goroutine
	go s.monitorXrayProcess()

	return nil
}

func (s *XrayService) StopXray() error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("Attempting to stop Xray...")
	if s.IsXrayRunning() {
		close(s.stopChan) // Signal the monitor to stop
		return p.Stop()
	}
	return errors.New("xray is not running")
}

func (s *XrayService) SetToNeedRestart() {
	isNeedXrayRestart.Store(true)
}

func (s *XrayService) IsNeedRestartAndSetFalse() bool {
	return isNeedXrayRestart.CompareAndSwap(true, false)
}
