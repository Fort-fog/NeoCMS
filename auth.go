package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Password hashing uses bcrypt. Because bcrypt silently truncates input at 72
// bytes, the password is pre-hashed with SHA-256 (base64) so long passphrases
// are honored in full and no length-extension ambiguity is introduced.
const bcryptCost = bcrypt.DefaultCost

// Login throttling: repeated failures for a single client IP produce a growing
// delay, and enough failures lock the address out outright.
const (
	loginFailWindow     = 15 * time.Minute
	loginFailSoftLimit  = 5              // after this many failures, add delay
	loginFailLockLimit  = 20             // after this many failures, lock out
	loginFailMaxDelay   = 5 * time.Second
	loginLockDuration   = 15 * time.Minute
	maxTrackedLoginIPs  = 10000
)

// Session lifetime.
const sessionLifetime = 24 * time.Hour

type Auth struct {
	mu       sync.RWMutex
	passHash string // bcrypt hash (or a legacy sha256 hex, migrated on success)
	sessions map[string]time.Time
	csrf     map[string]string // session token -> CSRF token
	path     string

	failMu    sync.Mutex
	failures  map[string]*failRecord
	lockUntil map[string]time.Time
}

type failRecord struct {
	count   int
	firstAt time.Time
}

type authData struct {
	PassHash string `json:"pass_hash"`
}

func NewAuth(path string) (*Auth, error) {
	a := &Auth{
		sessions:  make(map[string]time.Time),
		csrf:      make(map[string]string),
		path:      path,
		failures:  make(map[string]*failRecord),
		lockUntil: make(map[string]time.Time),
	}
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read auth: %w", err)
		}
		var ad authData
		if err := json.Unmarshal(data, &ad); err != nil {
			return nil, fmt.Errorf("parse auth: %w", err)
		}
		a.passHash = ad.PassHash
	}
	return a, nil
}

func (a *Auth) NeedsSetup() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.passHash == ""
}

// hashPassword turns a plaintext password into a bcrypt digest.
func hashPassword(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	enc := base64.StdEncoding.EncodeToString(sum[:])
	b, err := bcrypt.GenerateFromPassword([]byte(enc), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// isLegacySHA256 reports whether the stored hash is a bare 64-char hex digest
// from the previous implementation (unsalted SHA-256).
func isLegacySHA256(stored string) bool {
	if len(stored) != 64 {
		return false
	}
	_, err := hex.DecodeString(stored)
	return err == nil
}

func (a *Auth) SetPassword(password string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	a.mu.Lock()
	a.passHash = hash
	// Changing the password invalidates every existing session.
	a.sessions = make(map[string]time.Time)
	a.csrf = make(map[string]string)
	a.mu.Unlock()
	return a.save()
}

func (a *Auth) CheckPassword(password string) bool {
	a.mu.RLock()
	stored := a.passHash
	a.mu.RUnlock()
	if stored == "" {
		// Still run a bcrypt round so a missing password is not observable by
		// response timing.
		_ = bcrypt.CompareHashAndPassword([]byte(legacyDummyHash), []byte("x"))
		return false
	}

	if isLegacySHA256(stored) {
		sum := sha256.Sum256([]byte(password))
		candidate := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(stored)) != 1 {
			return false
		}
		// Transparently upgrade the old unsalted hash to bcrypt.
		if newHash, err := hashPassword(password); err == nil {
			a.mu.Lock()
			a.passHash = newHash
			a.mu.Unlock()
			if err := a.save(); err != nil {
				return false
			}
		}
		return true
	}

	sum := sha256.Sum256([]byte(password))
	enc := base64.StdEncoding.EncodeToString(sum[:])
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(enc)) == nil
}

// legacyDummyHash keeps the "no password configured" branch timing-equivalent.
const legacyDummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

// ThrottleLogin sleeps for a duration that grows with the number of recent
// failures from the client IP. Returns false once the address is locked out.
func (a *Auth) ThrottleLogin(ip string) bool {
	a.failMu.Lock()
	until, locked := a.lockUntil[ip]
	if locked {
		if time.Now().Before(until) {
			a.failMu.Unlock()
			return false
		}
		delete(a.lockUntil, ip)
		rec := a.failures[ip]
		if rec != nil {
			delete(a.failures, ip)
		}
	}

	rec := a.failures[ip]
	if rec == nil || time.Since(rec.firstAt) > loginFailWindow {
		a.failMu.Unlock()
		return true
	}
	count := rec.count
	a.failMu.Unlock()

	switch {
	case count >= loginFailLockLimit:
		a.failMu.Lock()
		a.lockUntil[ip] = time.Now().Add(loginLockDuration)
		delete(a.failures, ip)
		a.failMu.Unlock()
		return false
	case count >= loginFailSoftLimit:
		delay := time.Duration(count-loginFailSoftLimit+1) * 500 * time.Millisecond
		if delay > loginFailMaxDelay {
			delay = loginFailMaxDelay
		}
		time.Sleep(delay)
	}
	return true
}

// RecordLoginFailure counts a failed attempt for the IP.
func (a *Auth) RecordLoginFailure(ip string) {
	a.failMu.Lock()
	defer a.failMu.Unlock()
	if len(a.failures) >= maxTrackedLoginIPs {
		a.pruneFailuresLocked()
	}
	rec := a.failures[ip]
	if rec == nil || time.Since(rec.firstAt) > loginFailWindow {
		a.failures[ip] = &failRecord{count: 1, firstAt: time.Now()}
		return
	}
	rec.count++
}

// ClearLoginFailures resets the counter after a successful login.
func (a *Auth) ClearLoginFailures(ip string) {
	a.failMu.Lock()
	delete(a.failures, ip)
	delete(a.lockUntil, ip)
	a.failMu.Unlock()
}

func (a *Auth) pruneFailuresLocked() {
	now := time.Now()
	for ip, rec := range a.failures {
		if now.Sub(rec.firstAt) > loginFailWindow {
			delete(a.failures, ip)
		}
	}
	for ip, until := range a.lockUntil {
		if now.After(until) {
			delete(a.lockUntil, ip)
		}
	}
}

// CreateSession issues a session cookie and its paired CSRF token. The CSRF
// token is returned to callers that need to embed it in a form.
func (a *Auth) CreateSession(r *http.Request) (*http.Cookie, string) {
	token := generateToken()
	csrfToken := generateToken()

	a.mu.Lock()
	a.sessions[token] = time.Now().Add(sessionLifetime)
	a.csrf[token] = csrfToken
	a.mu.Unlock()

	secure := requestIsSecure(r)
	cookie := &http.Cookie{
		Name:     "neocms_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   int(sessionLifetime.Seconds()),
		SameSite: http.SameSiteLaxMode,
	}
	return cookie, csrfToken
}

// CSRFTokenFor returns the CSRF token bound to the request's session.
func (a *Auth) CSRFTokenFor(r *http.Request) string {
	c, err := r.Cookie("neocms_session")
	if err != nil || c.Value == "" {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.csrf[c.Value]
}

// ValidateCSRF compares the submitted token with the session's token in
// constant time.
func (a *Auth) ValidateCSRF(r *http.Request, submitted string) bool {
	if submitted == "" {
		return false
	}
	c, err := r.Cookie("neocms_session")
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.RLock()
	expected, ok := a.csrf[c.Value]
	a.mu.RUnlock()
	if !ok || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(submitted)) == 1
}

// DestroySession drops the session and its CSRF token.
func (a *Auth) DestroySession(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	delete(a.csrf, token)
	a.mu.Unlock()
}

// StartSessionCleanup periodically removes expired sessions and login counters.
func (a *Auth) StartSessionCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			a.sweepExpired()
		}
	}()
}

func (a *Auth) sweepExpired() {
	now := time.Now()
	a.mu.Lock()
	for token, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, token)
			delete(a.csrf, token)
		}
	}
	a.mu.Unlock()

	a.failMu.Lock()
	a.pruneFailuresLocked()
	a.failMu.Unlock()
}

func (a *Auth) IsAuthenticated(r *http.Request) bool {
	c, err := r.Cookie("neocms_session")
	if err != nil || c.Value == "" {
		return false
	}
	a.mu.RLock()
	exp, ok := a.sessions[c.Value]
	a.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		a.DestroySession(c.Value)
		return false
	}
	return true
}

// requestIsSecure reports whether the request arrived over TLS, honouring the
// reverse-proxy headers a deployment in front of a load balancer would set.
func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		if strings.EqualFold(strings.TrimSpace(strings.Split(proto, ",")[0]), "https") {
			return true
		}
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Ssl"), "on")
}

func (a *Auth) save() error {
	a.mu.RLock()
	ad := authData{PassHash: a.passHash}
	a.mu.RUnlock()
	data, err := json.MarshalIndent(ad, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
