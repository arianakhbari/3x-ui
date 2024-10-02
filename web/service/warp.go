package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"
	"x-ui/logger"
)

// WarpService struct with improved structuring
type WarpService struct {
	SettingService
	maxRetries int // Number of retries in case of failure
	httpClient *http.Client
}

// Initialize httpClient with optimized settings for Iran Irancell network (gRPC and TCP over VLESS)
func (s *WarpService) getHttpClient() *http.Client {
	if s.httpClient == nil {
		// Optimized transport for gRPC and TCP VLESS over high-latency networks (e.g., Iran Irancell)
		s.httpClient = &http.Client{
			Timeout: 45 * time.Second, // Increased timeout for long requests (gRPC and TCP)
			Transport: &http.Transport{
				// DialContext handles the TCP connection setup with increased timeouts for slow networks
				DialContext: (&net.Dialer{
					Timeout:   45 * time.Second, // Increase timeout for Iran Irancell latency
					KeepAlive: 45 * time.Second, // Keep connections alive longer for VLESS
				}).DialContext,
				MaxIdleConns:          150,              // Increase max idle connections for better reuse
				MaxIdleConnsPerHost:   20,               // Handle more simultaneous connections
				IdleConnTimeout:       120 * time.Second, // Longer idle timeout for gRPC/VLESS keep-alive
				TLSHandshakeTimeout:   15 * time.Second,  // Increase TLS handshake timeout for security
				ExpectContinueTimeout: 2 * time.Second,   // Handle continue expectations for HTTP2/gRPC
				ForceAttemptHTTP2:     true,              // Enable HTTP2 for better efficiency with gRPC
			},
		}
	}
	return s.httpClient
}

// Retry mechanism with exponential backoff and jitter
func (s *WarpService) doWithRetry(req *http.Request) (*http.Response, error) {
	client := s.getHttpClient()
	var resp *http.Response
	var err error

	if s.maxRetries == 0 {
		s.maxRetries = 3
	}

	// Use context with timeout for each request
	ctx, cancel := context.WithTimeout(req.Context(), 45*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	for i := 0; i <= s.maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		logger.Debug(fmt.Sprintf("Attempt %d failed: %s. Retrying...", i+1, err))

		// Exponential backoff with jitter
		backoff := time.Duration((1<<i)*500 + rand.Intn(500)) * time.Millisecond
		time.Sleep(backoff)
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

	// Read response body efficiently
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (s *WarpService) RegWarp(secretKey string, publicKey string) (string, error) {
	tos := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	hostName, _ := os.Hostname()

	// Use a struct and JSON marshalling
	regData := map[string]string{
		"key":   publicKey,
		"tos":   tos,
		"type":  "PC",
		"model": "x-ui",
		"name":  hostName,
	}
	dataBytes, err := json.Marshal(regData)
	if err != nil {
		return "", err
	}

	url := "https://api.cloudflareclient.com/v0a2158/reg"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(dataBytes))
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

	// Read response body efficiently
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var rspData map[string]interface{}
	err = json.Unmarshal(body, &rspData)
	if err != nil {
		return "", err
	}

	deviceId, ok := rspData["id"].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid 'id' in response data")
	}

	token, ok := rspData["token"].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid 'token' in response data")
	}

	accountMap, ok := rspData["account"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing or invalid 'account' in response data")
	}
	license, ok := accountMap["license"].(string)
	if !ok {
		return "", fmt.Errorf("missing or invalid 'license' in account data")
	}

	warpData := map[string]string{
		"access_token": token,
		"device_id":    deviceId,
		"license_key":  license,
		"private_key":  secretKey,
	}
	warpDataBytes, err := json.MarshalIndent(warpData, "", "  ")
	if err != nil {
		return "", err
	}

	err = s.SettingService.SetWarp(string(warpDataBytes))
	if err != nil {
		return "", err
	}

	result := fmt.Sprintf("{\n  \"data\": %s,\n  \"config\": %s\n}", string(warpDataBytes), string(body))

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

	// Use a struct and JSON marshalling
	licenseData := map[string]string{
		"license": license,
	}
	dataBytes, err := json.Marshal(licenseData)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(dataBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+warpData["access_token"])
	req.Header.Set("Content-Type", "application/json")

	// Make the request with retries
	resp, err := s.doWithRetry(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body efficiently
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	warpData["license_key"] = license
	newWarpData, err := json.MarshalIndent(warpData, "", "  ")
	if err != nil {
		return "", err
	}

	err = s.SettingService.SetWarp(string(newWarpData))
	if err != nil {
		return "", err
	}

	return string(newWarpData), nil
}
