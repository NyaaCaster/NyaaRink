package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func fixturePost(api DeviceAPI, secret, action, path string) (map[string]any, error) {
	body, _ := json.Marshal(map[string]string{"action": action, "path": path})
	request, e := http.NewRequest("POST", api.State.Bootstrap.Origin+"/fixture", bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = api.State.tlsConfig
	defer transport.CloseIdleConnections()
	response, e := (&http.Client{Transport: transport, Timeout: 30 * time.Second}).Do(request)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("fixture HTTP %d", response.StatusCode)
	}
	var result map[string]any
	e = json.NewDecoder(response.Body).Decode(&result)
	return result, e
}
