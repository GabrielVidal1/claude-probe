// Package store keeps what the probe measured: one SQLite file of records —
// `call` (one per tool call; a call is re-sent while it runs, the newest
// version wins), `mark` (a turn or subagent boundary, with the plan and the
// usage reading) and `usage` (an official reading the status line saw).
//
// Readers (`report`, `top`, `export`, the status line) open it while the
// daemon writes: WAL mode and a busy timeout make that safe.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	KeepDays = 30
	schema   = `
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at REAL, kind TEXT, session TEXT, key TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS records_key ON records (kind, key);
CREATE INDEX IF NOT EXISTS records_session ON records (session, kind);
CREATE INDEX IF NOT EXISTS records_at ON records (at);`
)

type Store struct {
	db *sql.DB
	mu sync.Mutex
}

// Record is one stored version; Data is the record's JSON.
type Record struct {
	ID      int64           `json:"id"`
	At      float64         `json:"at"`
	Kind    string          `json:"kind"`
	Session string          `json:"session"`
	Key     string          `json:"key"`
	Data    json.RawMessage `json:"data"`
}

// Open opens (and, unless readOnly, creates) the store.
func Open(path string, readOnly bool) (*Store, error) {
	if !readOnly {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(3000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	if readOnly {
		dsn += "&mode=ro"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if !readOnly {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, err
		}
		_ = os.Chmod(path, 0o600)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// Put stores a new version of a record.
func (s *Store) Put(kind, session, key string, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO records (at, kind, session, key, data) VALUES (?,?,?,?,?)`,
		now(), kind, session, key, string(raw))
	return err
}

func scan(rows *sql.Rows) ([]Record, error) {
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var data string
		if err := rows.Scan(&r.ID, &r.At, &r.Kind, &r.Session, &r.Key, &data); err != nil {
			return nil, err
		}
		r.Data = json.RawMessage(data)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Since returns the records after id `after` (the ai-agent hub's cursor).
func (s *Store) Since(after int64, limit int) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, at, kind, session, key, data FROM records
	  WHERE id > ? ORDER BY id LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	return scan(rows)
}

// LastID is the newest record's id (0 when empty).
func (s *Store) LastID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var id sql.NullInt64
	_ = s.db.QueryRow(`SELECT MAX(id) FROM records`).Scan(&id)
	return id.Int64
}

// Latest returns the newest version of every record of `kind` — for one
// session, or (session "") all of them since `since` (epoch seconds).
func (s *Store) Latest(kind, session string, since float64) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := `SELECT id, at, kind, session, key, data FROM records WHERE id IN (
	  SELECT MAX(id) FROM records WHERE kind = ?`
	args := []any{kind}
	if session != "" {
		q += ` AND session = ?`
		args = append(args, session)
	}
	if since > 0 {
		q += ` AND at >= ?`
		args = append(args, since)
	}
	q += ` GROUP BY key) ORDER BY id`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scan(rows)
}

// LastSession is the session of the newest call (`report` with no id).
func (s *Store) LastSession() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sid sql.NullString
	_ = s.db.QueryRow(`SELECT session FROM records WHERE kind = 'call' ORDER BY id DESC LIMIT 1`).Scan(&sid)
	return sid.String
}

// Newest is the newest record of `kind` with `key` (nil if none).
func (s *Store) Newest(kind, key string) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, at, kind, session, key, data FROM records
	  WHERE kind = ? AND key = ? ORDER BY id DESC LIMIT 1`, kind, key)
	if err != nil {
		return nil
	}
	rs, err := scan(rows)
	if err != nil || len(rs) == 0 {
		return nil
	}
	return &rs[0]
}

// Prune drops what is older than KeepDays, and superseded versions of a
// record once the hub has had an hour to read them.
func (s *Store) Prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := now()
	if _, err := s.db.Exec(`DELETE FROM records WHERE at < ?`, t-KeepDays*86400); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM records WHERE at < ? AND id NOT IN
	  (SELECT MAX(id) FROM records GROUP BY kind, key)`, t-3600)
	return err
}

// Cwd is where a session's calls and turns ran from.
type Cwd struct {
	Session string
	Cwd     string
	At      float64 // the last time
}

// Cwds lists the (session, cwd) pairs the hooks reported since `since`.
func (s *Store) Cwds(since float64) ([]Cwd, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT session, json_extract(data, '$.cwd') AS cwd, MAX(at) FROM records
	  WHERE kind IN ('call', 'mark') AND at >= ? AND cwd IS NOT NULL AND cwd != ''
	  GROUP BY session, cwd`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cwd
	for rows.Next() {
		var c Cwd
		if err := rows.Scan(&c.Session, &c.Cwd, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Strings lists the distinct non-empty values of one JSON field of a kind's
// records (e.g. every configDir the marks named).
func (s *Store) Strings(kind, field string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT DISTINCT json_extract(data, ?) AS v FROM records
	  WHERE kind = ? AND v IS NOT NULL AND v != ''`, "$."+field, kind)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil {
			out = append(out, v)
		}
	}
	return out
}
