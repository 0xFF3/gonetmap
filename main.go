package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "путь к YAML-конфигурации")
	flag.Parse()

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("ошибка: %v", err)
	}

	store, err := OpenStore(cfg.Database.Path)
	if err != nil {
		log.Fatalf("ошибка: %v", err)
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner := NewScanner(cfg.Scan, store)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner.Run(ctx)
	}()

	srv := &http.Server{
		Addr:              cfg.Web.Listen,
		Handler:           NewServer(store, scanner, cfg.Scan).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	log.Printf("веб-интерфейс: http://%s  (сети: %v, интервал: %s)", cfg.Web.Listen, cfg.Scan.Networks, cfg.Scan.Interval)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		stop()
		<-scanDone
		store.Close()
		log.Fatalf("веб-сервер: %v", err)
	}

	<-scanDone // дожидаемся остановки сканера, затем закрываем базу
	log.Print("остановлено")
}
