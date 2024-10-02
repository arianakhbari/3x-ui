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
    maxRetries int
    httpClient *http.Client
}

// Initialize httpClient if it's nil
func (s *WarpService) getHttpClient() *http.Client {
    if s.httpClient == nil {
        // Custom dialer with increased timeouts
        dialer := &net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 30 * time.Second,
        }

        s.httpClient = &http.Client{
            Timeout: 60 * time.Second, // Increased overall timeout
            Transport: &http.Transport{
                DialContext:         dialer.DialContext,
                MaxIdleConns:        200,
                MaxIdleConnsPerHost: 100,
                IdleConnTimeout:     90 * time.Second,
                TLSHandshakeTimeout: 15 * time.Second,
                ExpectContinueTimeout: 1 * time.Second,
                TLSClientConfig: &tls.Config{
                    MinVersion: tls.VersionTLS12,
                },
                ForceAttemptHTTP2: true, // Enable HTTP/2 if supported
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
        s.maxRetries = 5 // Increased max retries
    }

    maxBackoff := 15 * time.Second
    baseDelay := 500 * time.Millisecond

    for i := 0; i <= s.maxRetries; i++ {
        // Create a context with timeout for each request attempt
        ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
        defer cancel()

        // Clone the request with the new context
        reqWithCtx := req.Clone(ctx)

        resp, err = client.Do(reqWithCtx)
        if err == nil {
            return resp, nil
        }

        // Enhanced error logging
        logger.Error(fmt.Sprintf("Attempt %d failed: %s", i+1, err.Error()))

        if i < s.maxRetries {
            // Exponential backoff with jitter
            backoff := time.Duration(float64(baseDelay.Nanoseconds())*math.Pow(2, float64(i))) * time.Nanosecond
            jitter := time.Duration(rand.Int63n(int64(baseDelay)))
            sleepDuration := backoff + jitter
            if sleepDuration > maxBackoff {
                sleepDuration = maxBackoff
            }
            time.Sleep(sleepDuration)
        }
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

    var result bytes.Buffer
    _, err = result.ReadFrom(resp.Body)
    if err != nil {
        return "", err
    }

    return result.String(), nil
}

func (s *WarpService) RegWarp(secretKey string, publicKey string) (string, error) {
    tos := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
    hostName, _ := os.Hostname()

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

    var rspData map[string]interface{}
    decoder := json.NewDecoder(resp.Body)
    err = decoder.Decode(&rspData)
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

    warpDataMap := map[string]string{
        "access_token": token,
        "device_id":    deviceId,
        "license_key":  license,
        "private_key":  secretKey,
    }

    warpDataBytes, err := json.MarshalIndent(warpDataMap, "", "  ")
    if err != nil {
        return "", err
    }

    s.SettingService.SetWarp(string(warpDataBytes))

    resultMap := map[string]interface{}{
        "data":   warpDataMap,
        "config": rspData,
    }

    resultBytes, err := json.MarshalIndent(resultMap, "", "  ")
    if err != nil {
        return "", err
    }

    return string(resultBytes), nil
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

    // Update warpData with the new license
    warpData["license_key"] = license
    newWarpDataBytes, err := json.MarshalIndent(warpData, "", "  ")
    if err != nil {
        return "", err
    }
    s.SettingService.SetWarp(string(newWarpDataBytes))
    println(string(newWarpDataBytes))

    return string(newWarpDataBytes), nil
}
