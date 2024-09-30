package service

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
}

// Function to create a custom HTTP client with timeout and connection pooling
func (s *WarpService) createHttpClient() *http.Client {
	// Timeout of 10 seconds to handle potential network issues
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10, // Keep connections alive for re-use
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
		},
	}
}

// Retry mechanism with exponential backoff
func (s *WarpService) doWithRetry(req *http.Request) (*http.Response, error) {
	client := s.createHttpClient()
	var resp *http.Response
	var err error

	for i := 0; i <= s.maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil {
			return resp, nil
		}
		logger.Debug(fmt.Sprintf("Attempt %d failed: %s. Retrying...", i+1, err.Error()))

		// Exponential backoff
		time.Sleep(time.Duration((1<<i) * 500) * time.Millisecond)
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

	buffer := bytes.NewBuffer(make([]byte, 8192))
	buffer.Reset()
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func (s *WarpService) RegWarp(secretKey string, publicKey string) (string, error) {
	tos := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	hostName, _ := os.Hostname()
	data := fmt.Sprintf(`{"key":"%s","tos":"%s","type": "PC","model": "x-ui", "name": "%s"}`, publicKey, tos, hostName)

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

	buffer := bytes.NewBuffer(make([]byte, 8192))
	buffer.Reset()
	_, err = buffer.ReadFrom(resp.Body)
	if err != nil {
		return "", err
	}

	var rspData map[string]interface{}
	err = json.Unmarshal(buffer.Bytes(), &rspData)
	if err != nil {
		return "", err
	}

	deviceId := rspData["id"].(string)
	token := rspData["token"].(string)
	license, ok := rspData["account"].(map[string]interface{})["license"].(string)
	if !ok {
		logger.Debug("Error accessing license value.")
		return "", err
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
	data := fmt.Sprintf(`{"license": "%s"}`, license)

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

	buffer := bytes.NewBuffer(make([]byte, 8192))
	buffer.Reset()
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
