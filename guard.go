package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type GuardInfoResponse struct {
	AutheliaRunning   bool              `json:"authelia_running"`
	AutheliaContainer string            `json:"authelia_container"`
	AutheliaImage     string            `json:"authelia_image"`
	AutheliaUptime    string            `json:"authelia_uptime"`
	HostConfigPath    string            `json:"host_config_path"`
	Mounts            map[string]string `json:"mounts"`
	Env               map[string]string `json:"env"`
}

func runGuard() {
	guardListen := listenAddr
	if guardListen == ":8080" {
		guardListen = ":2375"
	}
	log.Printf("[guard] Authelia Docker Guard starting on %s...", guardListen)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/guard/info", handleGuardInfo)
	mux.HandleFunc("/api/guard/status", handleGuardInfo)
	mux.HandleFunc("/api/guard/restart", handleGuardRestart)
	mux.HandleFunc("/api/guard/logs", handleGuardLogs)

	server := &http.Server{Addr: guardListen, Handler: mux, ReadTimeout: 30 * time.Second}
	log.Fatal(server.ListenAndServe())
}

func unixDialer() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", dockerSocket)
			},
		},
		Timeout: 10 * time.Second,
	}
}

func findTargetContainer(client *http.Client) (string, error) {
	resp, err := client.Get("http://localhost/containers/json?all=true")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var containers []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Image string   `json:"Image"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return "", err
	}

	target := strings.ToLower(autheliaContainerName)
	for _, c := range containers {
		for _, name := range c.Names {
			cleanName := strings.TrimPrefix(strings.ToLower(name), "/")
			if cleanName == target || strings.Contains(cleanName, "authelia") {
				return c.ID, nil
			}
		}
		if strings.Contains(strings.ToLower(c.Image), "authelia") {
			return c.ID, nil
		}
	}
	return "", fmt.Errorf("authelia container not found")
}

func handleGuardInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	client := unixDialer()
	cid, err := findTargetContainer(client)
	if err != nil {
		json.NewEncoder(w).Encode(GuardInfoResponse{AutheliaRunning: false, AutheliaContainer: "not found"})
		return
	}

	resp, err := client.Get("http://localhost/containers/" + cid + "/json")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	var insp struct {
		Name  string `json:"Name"`
		Image string `json:"Image"`
		State struct {
			Running   bool   `json:"Running"`
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
		Config struct {
			Env []string `json:"Env"`
		} `json:"Config"`
		Mounts []struct {
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
		} `json:"Mounts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&insp); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	mountsMap := make(map[string]string)
	hostConfig := ""
	for _, m := range insp.Mounts {
		mountsMap[m.Destination] = m.Source
		if m.Destination == "/config" {
			hostConfig = m.Source
		}
	}
	envMap := make(map[string]string)
	for _, e := range insp.Config.Env {
		if parts := strings.SplitN(e, "=", 2); len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	uptimeStr := "stopped"
	if insp.State.Running {
		if t, err := time.Parse(time.RFC3339Nano, insp.State.StartedAt); err == nil {
			d := time.Since(t).Truncate(time.Second)
			h := int(d.Hours())
			uptimeStr = fmt.Sprintf("%dd %dh %dm", h/24, h%24, int(d.Minutes())%60)
		} else {
			uptimeStr = "running"
		}
	}

	json.NewEncoder(w).Encode(GuardInfoResponse{
		AutheliaRunning:   insp.State.Running,
		AutheliaContainer: strings.TrimPrefix(insp.Name, "/"),
		AutheliaImage:     insp.Image,
		AutheliaUptime:    uptimeStr,
		HostConfigPath:    hostConfig,
		Mounts:            mountsMap,
		Env:               envMap,
	})
}

func handleGuardRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", 405)
		return
	}
	client := unixDialer()
	cid, err := findTargetContainer(client)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	resp, err := client.Post("http://localhost/containers/"+cid+"/restart", "application/json", nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"restarted"}`))
}

func handleGuardLogs(w http.ResponseWriter, r *http.Request) {
	client := unixDialer()
	cid, err := findTargetContainer(client)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "150"
	}
	resp, err := client.Get("http://localhost/containers/" + cid + "/logs?stdout=true&stderr=true&tail=" + tail + "&timestamps=true")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) > 8 {
			line = line[8:]
		}
		w.Write(line)
		w.Write([]byte("\n"))
	}
}
