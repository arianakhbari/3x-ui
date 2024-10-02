package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
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
		dnsResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 10 * time.Second,
				}
				// Use a reliable DNS server
				return d.DialContext(ctx, "udp", "1.1.1.1:53") // Cloudflare DNS
			},
		}

		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  dnsResolver,
		}

		s.httpClient = &http.Client{
			Timeout: 60 * time.Second, // Increased timeout
			Transport: &http.Transport{
				DialContext:         dialer.DialContext,
				MaxIdleConns:        200,              // Increased for better performance
				MaxIdleConnsPerHost: 100,              // Increased per-host connections
				IdleConnTimeout:     90 * time.Second, // Increased idle timeout
				TLSHandshakeTimeout: 15 * time.Second, // Increased TLS handshake timeout
				ForceAttemptHTTP2:   true,             // Enable HTTP/2
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
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
		s.maxRetries = 5 // Increased retries
	}

	for i := 0; i <= s.maxRetries; i++ {
		// Create a context with timeout for each request
		ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
		defer cancel()

		req = req.WithContext(ctx)

		startTime := time.Now()
		resp, err = client.Do(req)
		duration := time.Since(startTime)

		if err == nil {
			logger.Info(fmt.Sprintf("Request succeeded in %v ms", duration.Milliseconds()))
			return resp, nil
		}

		logger.Error(fmt.Sprintf("Attempt %d failed after %v ms: %s. Retrying...", i+1, duration.Milliseconds(), err.Error()))

		// Exponential backoff with jitter
		backoff := time.Duration((1<<i)*500) * time.Millisecond
		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		time.Sleep(backoff + jitter)
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

	// Optionally decompress the response if compressed
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
	data := fmt.Sprintf(`{"key":"%s","tos":"%s","type": "PC","model": "x-ui", "name": "%s"}`, publicKey, tos, hostName)

	url := "https://api.cloudflareclient.com/v0a2158/reg"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
	if err != nil {
		return "", err
	}

	req.Header.Add("CF-Client-Version", "a-7.21-0721")
	req.Header.Add("Content-Type", "application/json")
	// Request compressed response
	req.Header.Add("Accept-Encoding", "gzip")

	// Make the request with retries
	resp, err := s.doWithRetry(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Handle compressed response
	var reader *bytes.Buffer
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err = decompressGZIP(resp.Body)
		if err != nil {
			return "", err
		}
	} else {
		reader = new(bytes.Buffer)
		_, err = reader.ReadFrom(resp.Body)
		if err != nil {
			return "", err
		}
	}

	var rspData map[string]interface{}
	err = json.Unmarshal(reader.Bytes(), &rspData)
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

	warpData := fmt.Sprintf("{\n  \"access_token\": \"%s\",\n  \"device_id\": \"%s\",", token, deviceId)
	warpData += fmt.Sprintf("\n  \"license_key\": \"%s\",\n  \"private_key\": \"%s\"\n}", license, secretKey)

	s.SettingService.SetWarp(warpData)

	result := fmt.Sprintf("{\n  \"data\": %s,\n  \"config\": %s\n}", warpData, reader.String())

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
	// Request compressed response
	req.Header.Add("Accept-Encoding", "gzip")

	// Make the request with retries
	resp, err := s.doWithRetry(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Handle compressed response
	var reader *bytes.Buffer
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err = decompressGZIP(resp.Body)
		if err != nil {
			return "", err
		}
	} else {
		reader = new(bytes.Buffer)
		_, err = reader.ReadFrom(resp.Body)
		if err != nil {
			return "", err
		}
	}

	warpData["license_key"] = license
	newWarpData, err := json.MarshalIndent(warpData, "", "  ")
	if err != nil {
		return "", err
	}
	s.SettingService.SetWarp(string(newWarpData))
	fmt.Println(string(newWarpData))

	return string(newWarpData), nil
}

// Helper function to decompress GZIP responses
func decompressGZIP(body io.Reader) (*bytes.Buffer, error) {
	gzipReader, err := gzip.NewReader(body)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(gzipReader)
	if err != nil {
		return nil, err
	}

	return &buffer, nil
}
