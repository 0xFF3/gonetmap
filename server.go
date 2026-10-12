package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"time"
)

//go:embed web
var webFS embed.FS

type Server struct {
	store    *Store
	scanner  *Scanner
	networks []string
}

func NewServer(store *Store, scanner *Scanner, cfg ScanConfig) *Server {
	nets := make([]string, len(cfg.Prefixes))
	for i, p := range cfg.Prefixes {
		nets[i] = p.String()
	}
	return &Server{store: store, scanner: scanner, networks: nets}
}

func (s *Server) Handler() http.Handler {
	static, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/hosts", s.handleHosts)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.Handle("GET /", http.FileServerFS(static))
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ответ API: %v", err)
	}
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		log.Printf("список хостов: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "не удалось прочитать базу"})
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	running, next := s.scanner.State()

	resp := struct {
		Running  bool       `json:"running"`
		LastScan *time.Time `json:"last_scan"`
		NextScan *time.Time `json:"next_scan"`
		Networks []string   `json:"networks"`
	}{Running: running, Networks: s.networks}

	if t, ok := s.store.LastScan(); ok {
		resp.LastScan = &t
	}
	if !running && !next.IsZero() {
		resp.NextScan = &next
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if !s.scanner.Trigger() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "сканирование уже идёт"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "запущено"})
}
