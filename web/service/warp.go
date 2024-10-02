import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
	"x-ui/logger"
)

type WarpService struct {
	SettingService
	maxRetries int // Number of retries in case of failure
	httpClient *http.Client
}

// Initialize httpClient if it's nil
func (s *WarpService) getHttpClient() *http.Client {
	if s.httpClient == nil {
		s.httpClient = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		}
	}
	return s.httpClient
}

// Retry mechanism with exponential backoff
func (s *WarpService) doWithRetry(req *http.Request) (*http.Response, error) {
	client := s.getHttpClient()
	var resp *http.Response
	var err error

	if s.maxRetries == 0 {
		s.maxRetries = 3
	}

	for i := 0; i <= s.maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil {
			return resp, nil
		}
		logger.Debug(fmt.Sprintf("Attempt %d failed: %s. Retrying...", i+1, err.Error()))

		// Exponential backoff
		time.Sleep(time.Duration((1<<i)*500) * time.Millisecond)
	}

	return nil, fmt.Errorf("all retry attempts failed: %v", err)
}

func (s *WarpService) GetWarpConfig() (string, error) {
	var warpData map[string]string
	warp, err := s.SettingService.GetWarp()
	if err != nil {
		return "", err
	}
	err = json.Unmarshal([]byte(warp), &warpData)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.cloudflareclient.com/v0a2158/reg/%s", warpData["device_id"])

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+warpData["access_token"])

	// Make the request with retries
	resp, err := s.doWithRetry(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func (s *WarpService) RegWarp(secretKey string, publicKey string) (string, error) {
	tos := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	hostName, _ := os.Hostname()
	data := fmt.Sprintf({"key":"%s","tos":"%s","type": "PC","model": "x-ui", "name": "%s"}, publicKey, tos, hostName)

	url := "https://api.cloudflareclient.com/v0a2158/reg"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return "", err
	}

	req.Header.Add("CF-Client-Version", "a-7.21-0721")
	req.Header.Add("Content-Type", "application/json")

	// Make the request with retries
	resp, err := s.doWithRetry(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return "", err
	}

	var rspData map[string]interface{}
	err = json.Unmarshal(buffer.Bytes(), &rspData)
	if err != nil {
		return "", err
	}

	deviceIdInterface, ok := rspData["id"]
	if !ok {
		return "", fmt.Errorf("missing 'id' in response data")
	}
	deviceId, ok := deviceIdInterface.(string)
	if !ok {
		return "", fmt.Errorf("'id' is not a string")
	}

	tokenInterface, ok := rspData["token"]
	if !ok {
		return "", fmt.Errorf("missing 'token' in response data")
	}
	token, ok := tokenInterface.(string)
	if !ok {
		return "", fmt.Errorf("'token' is not a string")
	}

	accountInterface, ok := rspData["account"]
	if !ok {
		return "", fmt.Errorf("missing 'account' in response data")
	}
	accountMap, ok := accountInterface.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("'account' is not a map")
	}
	licenseInterface, ok := accountMap["license"]
	if !ok {
		return "", fmt.Errorf("missing 'license' in account data")
	}
	license, ok := licenseInterface.(string)
	if !ok {
		return "", fmt.Errorf("'license' is not a string")
	}

	warpData := fmt.Sprintf("{\n  \"access_token\": \"%s\",\n  \"device_id\": \"%s\",", token, deviceId)
	warpData += fmt.Sprintf("\n  \"license_key\": \"%s\",\n  \"private_key\": \"%s\"\n}", license, secretKey)

	s.SettingService.SetWarp(warpData)

	result := fmt.Sprintf("{\n  \"data\": %s,\n  \"config\": %s\n}", warpData, buffer.String())

	return result, nil
}

func (s *WarpService) SetWarpLicense(license string) (string, error) {
	var warpData map[string]string
	warp, err := s.SettingService.GetWarp()
	if err != nil {
		return "", err
	}
	err = json.Unmarshal([]byte(warp), &warpData)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.cloudflareclient.com/v0a2158/reg/%s/account", warpData["device_id"])
	data := fmt.Sprintf({"license": "%s"}, license)

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+warpData["access_token"])

	// Make the request with retries
	resp, err := s.doWithRetry(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return "", err
	}

	warpData["license_key"] = license
	newWarpData, err := json.MarshalIndent(warpData, "", "  ")
	if err != nil {
		return "", err
	}
	s.SettingService.SetWarp(string(newWarpData))
	println(string(newWarpData))

	return string(newWarpData), nil
}

