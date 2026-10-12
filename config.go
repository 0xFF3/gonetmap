package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Scan     ScanConfig `yaml:"scan"`
	Database struct {
		Path string `yaml:"path"`
	} `yaml:"database"`
	Web struct {
		Listen string `yaml:"listen"`
	} `yaml:"web"`
}

type ScanConfig struct {
	Networks     []string      `yaml:"networks"`
	Interval     time.Duration `yaml:"interval"`
	Timeout      time.Duration `yaml:"timeout"`
	Concurrency  int           `yaml:"concurrency"`
	Methods      []string      `yaml:"methods"`
	TCPPorts     []int         `yaml:"tcp_ports"`
	ResolveNames bool          `yaml:"resolve_names"`
	ForgetAfter  time.Duration `yaml:"forget_after"`

	// Заполняется при валидации из Networks.
	Prefixes []netip.Prefix `yaml:"-"`
}

func LoadConfig(path string) (*Config, error) {
	// Значения по умолчанию; YAML перезаписывает только то, что в нём указано.
	cfg := &Config{
		Scan: ScanConfig{
			Interval:     5 * time.Minute,
			Timeout:      time.Second,
			Concurrency:  128,
			Methods:      []string{"ping", "tcp"},
			TCPPorts:     []int{22, 80, 443, 445, 3389},
			ResolveNames: true,
		},
	}
	cfg.Database.Path = "ipmanager.db"
	cfg.Web.Listen = "127.0.0.1:8080"

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // опечатки в ключах считаем ошибкой
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("разбор %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("конфигурация %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	s := &c.Scan

	if len(s.Networks) == 0 {
		return errors.New("scan.networks: укажите хотя бы одну сеть")
	}
	for _, n := range s.Networks {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return fmt.Errorf("scan.networks: %q: %w", n, err)
		}
		if !p.Addr().Is4() {
			return fmt.Errorf("scan.networks: %q: поддерживается только IPv4", n)
		}
		if p.Bits() < 16 {
			return fmt.Errorf("scan.networks: %q: сеть слишком большая (минимум /16)", n)
		}
		s.Prefixes = append(s.Prefixes, p.Masked())
	}

	if s.Interval < 10*time.Second {
		return errors.New("scan.interval: минимум 10s")
	}
	if s.Timeout <= 0 {
		return errors.New("scan.timeout: должен быть больше нуля")
	}
	if s.Concurrency < 1 || s.Concurrency > 1024 {
		return errors.New("scan.concurrency: допустимо от 1 до 1024")
	}
	if len(s.Methods) == 0 {
		return errors.New("scan.methods: укажите ping и/или tcp")
	}
	for _, m := range s.Methods {
		if m != "ping" && m != "tcp" {
			return fmt.Errorf("scan.methods: неизвестный метод %q (доступны: ping, tcp)", m)
		}
	}
	if slices.Contains(s.Methods, "tcp") {
		if len(s.TCPPorts) == 0 {
			return errors.New("scan.tcp_ports: нужен хотя бы один порт для метода tcp")
		}
		for _, port := range s.TCPPorts {
			if port < 1 || port > 65535 {
				return fmt.Errorf("scan.tcp_ports: неверный порт %d", port)
			}
		}
	}
	if s.ForgetAfter < 0 {
		return errors.New("scan.forget_after: не может быть отрицательным")
	}
	if c.Database.Path == "" {
		return errors.New("database.path: не задан")
	}
	if c.Web.Listen == "" {
		return errors.New("web.listen: не задан")
	}
	return nil
}
