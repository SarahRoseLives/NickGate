package nickserv

import (
        "bytes"
        "encoding/json"
        "fmt"
        "net/http"
        "time"
)

// AuthClient handles authentication with the Ergo API
type AuthClient struct {
        apiURL    string
        token     string
        client    *http.Client
        userAgent string
}

// NewAuthClient creates a new NickServ authentication client
func NewAuthClient(apiURL, token string) *AuthClient {
        return &AuthClient{
                apiURL: apiURL,
                token:  token,
                client: &http.Client{
                        Timeout: 10 * time.Second,
                },
                userAgent: "NickGate/1.0",
        }
}

// AuthRequest represents the authentication request payload
type AuthRequest struct {
        AccountName string `json:"accountName"`
        Passphrase  string `json:"passphrase"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
        Success bool   `json:"success"`
        Message string `json:"message,omitempty"`
}

// Authenticate verifies credentials with Ergo API
func (a *AuthClient) Authenticate(accountName, passphrase string) (bool, error) {
        reqBody := AuthRequest{
                AccountName: accountName,
                Passphrase:  passphrase,
        }

        jsonData, err := json.Marshal(reqBody)
        if err != nil {
                return false, fmt.Errorf("failed to marshal request: %w", err)
        }

        req, err := http.NewRequest("POST", a.apiURL, bytes.NewBuffer(jsonData))
        if err != nil {
                return false, fmt.Errorf("failed to create request: %w", err)
        }

        req.Header.Set("Authorization", "Bearer "+a.token)
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("User-Agent", a.userAgent)

        resp, err := a.client.Do(req)
        if err != nil {
                return false, fmt.Errorf("request to NickServ API failed: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                return false, fmt.Errorf("NickServ API returned status %d", resp.StatusCode)
        }

        var authResp AuthResponse
        if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
                return false, fmt.Errorf("failed to decode NickServ response: %w", err)
        }

        if !authResp.Success && authResp.Message != "" {
                return false, fmt.Errorf("NickServ authentication failed: %s", authResp.Message)
        }

        return authResp.Success, nil
}

// Ping checks if the Ergo API is reachable
func (a *AuthClient) Ping() error {
        req, err := http.NewRequest("HEAD", a.apiURL, nil)
        if err != nil {
                return fmt.Errorf("failed to create ping request: %w", err)
        }

        req.Header.Set("Authorization", "Bearer "+a.token)
        req.Header.Set("User-Agent", a.userAgent)

        resp, err := a.client.Do(req)
        if err != nil {
                return fmt.Errorf("ping to NickServ API failed: %w", err)
        }
        resp.Body.Close()

        if resp.StatusCode >= 400 {
                return fmt.Errorf("NickServ API returned status %d", resp.StatusCode)
        }

        return nil
}
