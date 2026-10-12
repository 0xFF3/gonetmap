package main

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	_ "modernc.org/sqlite" // чистый Go, CGO не нужен
)

type Host struct {
	IP          string    `json:"ip"`
	Network     string    `json:"network"`
	Hostname    string    `json:"hostname"`
	MAC         string    `json:"mac"`
	Ports       string    `json:"ports"` // открытые порты через запятую
	Up          bool      `json:"up"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	LastChecked time.Time `json:"last_checked"`
}

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
	ip           TEXT PRIMARY KEY,
	ip_num       INTEGER NOT NULL,
	network      TEXT    NOT NULL,
	hostname     TEXT    NOT NULL DEFAULT '',
	mac          TEXT    NOT NULL DEFAULT '',
	ports        TEXT    NOT NULL DEFAULT '',
	is_up        INTEGER NOT NULL DEFAULT 0,
	first_seen   INTEGER NOT NULL,
	last_seen    INTEGER NOT NULL,
	last_checked INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hosts_network ON hosts(network);

CREATE TABLE IF NOT EXISTS scans (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	network     TEXT    NOT NULL,
	started_at  INTEGER NOT NULL,
	finished_at INTEGER NOT NULL,
	scanned     INTEGER NOT NULL,
	up          INTEGER NOT NULL
);
`

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Одно соединение: SQLite пишет в один поток, так проще избежать "database is locked".
	db.SetMaxOpenConns(1)

	for _, q := range []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA busy_timeout = 5000`,
		schema,
	} {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("инициализация базы: %w", err)
		}
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ipNum(a netip.Addr) int64 {
	b := a.As4()
	return int64(binary.BigEndian.Uint32(b[:]))
}

// SaveScan сохраняет результат сканирования одной сети: все ранее известные хосты сети
// помечаются как "не в сети", а найденные обновляются (или создаются).
func (s *Store) SaveScan(network string, started, finished time.Time, scanned int, up []Result) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := finished.Unix()

	if _, err := tx.Exec(
		`UPDATE hosts SET is_up = 0, last_checked = ? WHERE network = ?`, now, network,
	); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO hosts (ip, ip_num, network, hostname, mac, ports, is_up, first_seen, last_seen, last_checked)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			network      = excluded.network,
			hostname     = CASE WHEN excluded.hostname <> '' THEN excluded.hostname ELSE hosts.hostname END,
			mac          = CASE WHEN excluded.mac <> '' THEN excluded.mac ELSE hosts.mac END,
			ports        = excluded.ports,
			is_up        = 1,
			last_seen    = excluded.last_seen,
			last_checked = excluded.last_checked`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range up {
		if _, err := stmt.Exec(
			r.IP.String(), ipNum(r.IP), network, r.Hostname, r.MAC, r.PortsString(), now, now, now,
		); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO scans (network, started_at, finished_at, scanned, up) VALUES (?, ?, ?, ?, ?)`,
		network, started.Unix(), now, scanned, len(up),
	); err != nil {
		return err
	}
	// История сканирований нужна только для статуса — храним 30 дней.
	if _, err := tx.Exec(
		`DELETE FROM scans WHERE finished_at < ?`, finished.Add(-30*24*time.Hour).Unix(),
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`
		SELECT ip, network, hostname, mac, ports, is_up, first_seen, last_seen, last_checked
		FROM hosts ORDER BY ip_num`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hosts := []Host{} // не nil, чтобы в JSON был [] а не null
	for rows.Next() {
		var (
			h                     Host
			up                    int
			first, last, checked  int64
		)
		if err := rows.Scan(&h.IP, &h.Network, &h.Hostname, &h.MAC, &h.Ports,
			&up, &first, &last, &checked); err != nil {
			return nil, err
		}
		h.Up = up == 1
		h.FirstSeen = time.Unix(first, 0)
		h.LastSeen = time.Unix(last, 0)
		h.LastChecked = time.Unix(checked, 0)
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

// LastScan возвращает время завершения самого свежего сканирования.
func (s *Store) LastScan() (time.Time, bool) {
	var ts sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(finished_at) FROM scans`).Scan(&ts); err != nil || !ts.Valid {
		return time.Time{}, false
	}
	return time.Unix(ts.Int64, 0), true
}

// Prune удаляет хосты, которых нет в сети и которых не видели с момента before.
func (s *Store) Prune(before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM hosts WHERE is_up = 0 AND last_seen < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
