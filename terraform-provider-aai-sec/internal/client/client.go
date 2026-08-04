// Package client implements the bounded version-one machine API client.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 8 << 20

// Client calls only the versioned, service-identity-authenticated management API.
type Client struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

// New validates provider configuration without making a hidden network call.
func New(endpoint, token string, timeout time.Duration) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1") {
		return nil, fmt.Errorf("endpoint must be an absolute HTTPS URL (HTTP is allowed only for localhost)")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("endpoint must not contain user information, a query, or a fragment")
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("a service identity token is required")
	}
	if timeout < time.Second || timeout > 2*time.Minute {
		return nil, fmt.Errorf("request timeout must be between 1 and 120 seconds")
	}
	return &Client{
		baseURL: parsed,
		token:   token,
		http: &http.Client{
			Timeout: timeout,
			// Redirects are not part of the machine API contract. Refusing them
			// prevents a control-plane or proxy response from forwarding the
			// service bearer to another origin.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Do performs one bounded request and never logs or returns the bearer token.
func (c *Client) Do(ctx context.Context, method, path string, body, output any) error {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return fmt.Errorf("machine API path is invalid")
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		payload = bytes.NewReader(encoded)
	}
	target := *c.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + "/machine/v1/enterprise" + path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), payload)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("machine API request failed: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read machine API response: %w", err)
	}
	if len(responseBody) > maxResponseBytes {
		return fmt.Errorf("machine API response exceeds %d bytes", maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(responseBody, &problem) != nil || problem.Error == "" {
			problem.Error = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("machine API returned HTTP %d: %s", response.StatusCode, problem.Error)
	}
	if output != nil && len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, output); err != nil {
			return fmt.Errorf("decode machine API response: %w", err)
		}
	}
	return nil
}

// List loads one bounded server-owned collection.
func (c *Client) List(ctx context.Context, path string) ([]map[string]any, error) {
	var response struct {
		Items []map[string]any `json:"items"`
	}
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response.Items, nil
}

// Find returns one exact ID from a tenant-scoped collection.
func (c *Client) Find(ctx context.Context, path, id string) (map[string]any, bool, error) {
	items, err := c.List(ctx, path)
	if err != nil {
		return nil, false, err
	}
	for _, item := range items {
		if itemID, _ := item["id"].(string); itemID == id {
			return item, true, nil
		}
	}
	return nil, false, nil
}
