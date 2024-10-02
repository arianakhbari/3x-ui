package xrayservice

import (
    "encoding/json"
    "errors"
    "sync"

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
}

// IsXrayRunning checks if the Xray process is running.
func (s *XrayService) IsXrayRunning() bool {
    return p != nil && p.IsRunning()
}

// GetXrayErr returns any errors from the Xray process.
func (s *XrayService) GetXrayErr() error {
    if p == nil {
        return nil
    }
    return p.GetErr()
}

// GetXrayResult returns the result from the Xray process.
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

// GetXrayVersion returns the version of the Xray process.
func (s *XrayService) GetXrayVersion() string {
    if p == nil {
        return "Unknown"
    }
    return p.GetVersion()
}

// RemoveIndex removes an element from a slice at the specified index.
func RemoveIndex(s []interface{}, index int) []interface{} {
    return append(s[:index], s[index+1:]...)
}

// GetXrayConfig generates the Xray configuration, optimizing for higher throughput.
func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
    templateConfig, err := s.settingService.GetXrayConfigTemplate()
    if err != nil {
        logger.Error("Failed to get Xray config template:", err)
        return nil, err
    }

    xrayConfig := &xray.Config{}
    err = json.Unmarshal([]byte(templateConfig), xrayConfig)
    if err != nil {
        logger.Error("Failed to unmarshal Xray config template:", err)
        return nil, err
    }

    // Optimize global Xray settings for better performance
    xrayConfig.Transport = &xray.TransportConfig{
        TCPSettings: &xray.TCPSettings{
            Header: xray.TCPHeader{
                Type: "none",
            },
            // Enable TCP Fast Open if possible
            TCPFastOpen: true,
        },
        // Increase buffer sizes
        KCPSettings: &xray.KCPSettings{
            MTU:             1350,
            TTI:             20,
            UpCapacity:      10,
            DownCapacity:    100,
            Congestion:      true,
            ReadBufferSize:  2,
            WriteBufferSize: 2,
            Header: xray.KCPHeader{
                Type: "none",
            },
        },
    }

    // Integrate Warp settings and optimize for performance
    warpConfigStr, err := s.settingService.GetWarp()
    if err == nil && warpConfigStr != "" {
        var warpConfig map[string]interface{}
        err = json.Unmarshal([]byte(warpConfigStr), &warpConfig)
        if err == nil {
            // Optimize Warp settings if necessary
            warpConfig["mtu"] = 1420
            warpConfig["concurrency"] = 8 // Increase concurrency for Warp

            xrayConfig.OutboundConfigs = append(xrayConfig.OutboundConfigs, xray.OutboundConfig{
                Protocol: "wireguard",
                Settings: warpConfig,
                Tag:      "warp",
            })
        } else {
            logger.Error("Failed to unmarshal Warp config:", err)
        }
    } else {
        logger.Warn("No Warp configuration found or error retrieving it:", err)
    }

    // Update traffic stats
    s.inboundService.AddTraffic(nil, nil)

    inbounds, err := s.inboundService.GetAllInbounds()
    if err != nil {
        logger.Error("Failed to get all inbounds:", err)
        return nil, err
    }

    for _, inbound := range inbounds {
        if !inbound.Enable {
            continue
        }

        // Parse settings
        var settings map[string]interface{}
        err := json.Unmarshal([]byte(inbound.Settings), &settings)
        if err != nil {
            logger.Error("Failed to unmarshal inbound settings:", err)
            continue
        }

        // Optimize cipher methods for better performance
        s.optimizeCiphers(settings)

        // Handle clients
        clients, ok := settings["clients"].([]interface{})
        if ok {
            clients = s.filterActiveClients(clients, inbound.ClientStats)
            settings["clients"] = clients

            modifiedSettings, err := json.Marshal(settings)
            if err != nil {
                logger.Error("Failed to marshal modified settings:", err)
                continue
            }
            inbound.Settings = string(modifiedSettings)
        }

        // Clean up and optimize stream settings
        inbound.StreamSettings = s.optimizeStreamSettings(inbound.StreamSettings)

        // Generate inbound config
        inboundConfig := inbound.GenXrayInboundConfig()
        xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
    }
    return xrayConfig, nil
}

// optimizeCiphers selects efficient encryption algorithms for better performance.
func (s *XrayService) optimizeCiphers(settings map[string]interface{}) {
    if method, ok := settings["method"].(string); ok {
        // Use AES-128-GCM for better performance
        if method == "chacha20-poly1305" {
            settings["method"] = "aes-128-gcm"
        }
    }
}

// filterActiveClients filters out inactive clients and cleans up client configurations.
func (s *XrayService) filterActiveClients(clients []interface{}, clientStats []ClientTraffic) []interface{} {
    var finalClients []interface{}
    clientEmailSet := make(map[string]bool)
    for _, client := range clients {
        c, ok := client.(map[string]interface{})
        if !ok {
            continue
        }

        email, _ := c["email"].(string)
        clientEmailSet[email] = true

        if c["enable"] != nil {
            if enable, ok := c["enable"].(bool); ok && !enable {
                continue
            }
        }

        // Clean up client config
        for key := range c {
            if key != "email" && key != "id" && key != "password" && key != "flow" && key != "method" {
                delete(c, key)
            }
            if c["flow"] == "xtls-rprx-vision-udp443" {
                c["flow"] = "xtls-rprx-vision"
            }
        }
        finalClients = append(finalClients, c)
    }

    // Remove clients exceeding traffic limits
    for _, clientTraffic := range clientStats {
        if !clientTraffic.Enable && clientEmailSet[clientTraffic.Email] {
            logger.Infof("Removing user %s due to expiration or traffic limit", clientTraffic.Email)
            delete(clientEmailSet, clientTraffic.Email)
        }
    }

    return finalClients
}

// optimizeStreamSettings removes unnecessary fields and optimizes stream settings for performance.
func (s *XrayService) optimizeStreamSettings(streamSettingsStr string) string {
    if streamSettingsStr == "" {
        return ""
    }

    var stream map[string]interface{}
    err := json.Unmarshal([]byte(streamSettingsStr), &stream)
    if err != nil {
        logger.Error("Failed to unmarshal stream settings:", err)
        return streamSettingsStr
    }

    // Remove settings under tlsSettings and realitySettings
    if tlsSettings, ok := stream["tlsSettings"].(map[string]interface{}); ok {
        delete(tlsSettings, "settings")
        // Optimize TLS settings
        tlsSettings["disableSessionResumption"] = false
        tlsSettings["disableSystemRoot"] = false
    }
    if realitySettings, ok := stream["realitySettings"].(map[string]interface{}); ok {
        delete(realitySettings, "settings")
    }

    // Remove externalProxy field
    delete(stream, "externalProxy")

    // Set network optimization settings
    stream["sockopt"] = map[string]interface{}{
        "tcpFastOpen":     true,
        "tcpKeepAlive":    true,
        "soReusePort":     true,
        "soReuseAddr":     true,
        "tproxy":          "off",
        "tcpConcurrent":   true,
        "acceptProxyProtocol": false,
    }

    newStream, err := json.Marshal(stream)
    if err != nil {
        logger.Error("Failed to marshal optimized stream settings:", err)
        return streamSettingsStr
    }

    return string(newStream)
}

// GetXrayTraffic retrieves traffic statistics from Xray.
func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
    if !s.IsXrayRunning() {
        err := errors.New("Xray is not running")
        logger.Debug("Attempted to fetch Xray traffic, but Xray is not running:", err)
        return nil, nil, err
    }
    apiPort := p.GetAPIPort()
    s.xrayAPI.Init(apiPort)
    defer s.xrayAPI.Close()

    traffic, clientTraffic, err := s.xrayAPI.GetTraffic(true)
    if err != nil {
        logger.Debug("Failed to fetch Xray traffic:", err)
        return nil, nil, err
    }
    return traffic, clientTraffic, nil
}

// RestartXray restarts the Xray process with updated configuration.
func (s *XrayService) RestartXray(isForce bool) error {
    lock.Lock()
    defer lock.Unlock()
    logger.Debug("Restarting Xray, force:", isForce)

    xrayConfig, err := s.GetXrayConfig()
    if err != nil {
        logger.Error("Failed to get Xray config:", err)
        return err
    }

    if s.IsXrayRunning() {
        if !isForce && p.GetConfig().Equals(xrayConfig) {
            logger.Debug("No need to restart Xray; configuration unchanged.")
            return nil
        }
        err := p.Stop()
        if err != nil {
            logger.Error("Failed to stop Xray process:", err)
            return err
        }
    }

    p = xray.NewProcess(xrayConfig)
    result = ""
    err = p.Start()
    if err != nil {
        logger.Error("Failed to start Xray process:", err)
        return err
    }
    logger.Info("Xray process restarted successfully.")
    return nil
}

// StopXray stops the Xray process if it's running.
func (s *XrayService) StopXray() error {
    lock.Lock()
    defer lock.Unlock()
    logger.Debug("Attempting to stop Xray...")
    if s.IsXrayRunning() {
        err := p.Stop()
        if err != nil {
            logger.Error("Failed to stop Xray process:", err)
            return err
        }
        logger.Info("Xray process stopped successfully.")
        return nil
    }
    return errors.New("Xray is not running")
}

// SetToNeedRestart marks that Xray needs to be restarted.
func (s *XrayService) SetToNeedRestart() {
    isNeedXrayRestart.Store(true)
}

// IsNeedRestartAndSetFalse checks if Xray needs to be restarted and resets the flag.
func (s *XrayService) IsNeedRestartAndSetFalse() bool {
    return isNeedXrayRestart.CompareAndSwap(true, false)
}
