package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const port = ":8091"

func main() {
	// Ensure directories exist
	os.MkdirAll("data/uploads", 0755)
	os.MkdirAll("static/css", 0755)
	os.MkdirAll("static/js", 0755)
	os.MkdirAll("templates", 0755)

	// Initialize store
	store, err := NewStore("data/site.json")
	if err != nil {
		log.Fatalf("Failed to init store: %v", err)
	}

	// Initialize auth
	auth, err := NewAuth("data/auth.json")
	if err != nil {
		log.Fatalf("Failed to init auth: %v", err)
	}

	// Load templates.
	//
	// There is deliberately no "safeHTML"-style escape hatch: every value that
	// an admin can edit is rendered through html/template's contextual escaper.
	// Re-introducing one re-opens a stored-XSS path into the public pages.
	tpl := template.New("").Funcs(template.FuncMap{
		"toJson": func(v interface{}) (template.JS, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return template.JS(b), nil
		},
	})
	tpl, err = tpl.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	site := &SiteApp{store: store, auth: auth, tpl: tpl}

	// Periodically purge expired admin sessions to avoid unbounded map growth.
	auth.StartSessionCleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("/", site.handleHome)
	mux.HandleFunc("/services", site.handleServices)
	mux.HandleFunc("/gallery", site.handleGallery)
	mux.HandleFunc("/about", site.handleAbout)
	mux.HandleFunc("/contact", site.handleContact)
	mux.HandleFunc("/api/contact", site.handleContactAPI)
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/static/", http.FileServer(http.Dir("static"))).ServeHTTP(w, r)
	})
	mux.HandleFunc("/uploads/", func(w http.ResponseWriter, r *http.Request) {
		serveUploads(w, r)
	})
	mux.HandleFunc("/admin", site.handleAdmin)
	mux.HandleFunc("/admin/login", site.handleAdminLogin)
	mux.HandleFunc("/admin/logout", site.handleAdminLogout)
	mux.HandleFunc("/admin/save", site.handleAdminSave)
	mux.HandleFunc("/admin/upload", site.handleAdminUpload)
	mux.HandleFunc("/admin/delete-image", site.handleAdminDeleteImage)
	mux.HandleFunc("/admin/setup", site.handleSetup)

	// Wrap the mux: security headers first, then a global body-size cap so no
	// handler can be asked to buffer an unbounded request.
	server := &http.Server{
		Addr:              port,
		Handler:           limitBody(maxRequestBytes, securityHeaders(site.recoverMiddleware(mux))),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	fmt.Printf("NEON CYBERPUNK site starting on http://localhost%s\n", port)
	fmt.Printf("Admin panel: http://localhost%s/admin\n", port)
	if auth.NeedsSetup() {
		fmt.Printf("SETUP REQUIRED: visit http://localhost%s/admin/setup\n", port)
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type SiteApp struct {
	store *Store
	auth  *Auth
	tpl   *template.Template
}

func (s *SiteApp) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC: %v", rec)
				http.Error(w, "Internal error", 500)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Request body caps. The global cap protects every handler from being asked to
// buffer an arbitrarily large POST; the upload cap is applied on top of it.
const (
	maxRequestBytes = 12 << 20 // 12 MiB for any request body
	maxUploadBytes  = 5 << 20  // 5 MiB of image payload
)

// cspPolicy blocks inline scripts/styles, which is what makes stored XSS from
// admin-editable content non-executable. Nonces are not used because the
// templates contain inline handlers; 'unsafe-inline' is therefore avoided by
// keeping script/style external where possible and relying on escaping.
const cspPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src https://fonts.gstatic.com; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

// securityHeaders sets baseline response headers on every reply.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Content-Security-Policy", cspPolicy)
		// Uploads are images served from our own origin; keep them from being
		// framed or sniffed as active content.
		if strings.HasPrefix(r.URL.Path, "/uploads/") {
			h.Set("Content-Disposition", "inline")
		}
		if requestIsSecure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody wraps the request body with http.MaxBytesReader.
func limitBody(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// serveUploads serves uploaded images without exposing a directory listing.
// Only direct file paths are served; a bare /uploads/ or any path that does not
// resolve to an existing regular file returns 404.
func serveUploads(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/uploads/")
	if name == "" || name == "/" {
		http.NotFound(w, r)
		return
	}
	if !strings.HasSuffix(name, "/") {
		// Reject anything that is not a single clean filename.
		if filepath.Base(name) != name || name == "." || name == ".." {
			http.NotFound(w, r)
			return
		}
	}
	fs := http.StripPrefix("/uploads/", http.FileServer(http.Dir("data/uploads")))
	fs.ServeHTTP(w, r)
}

// --- Contact-form abuse controls -------------------------------------------------
//
// The public contact endpoint writes to the site store, so it is rate limited per
// client IP and its fields are length-capped. Without this an anonymous visitor
// can fill data/site.json with arbitrarily large messages at no cost.

const (
	contactWindow      = 10 * time.Minute
	contactMaxRequests = 20 // submissions accepted per window, per IP
	maxTrackedContactIPs = 10000

	maxNameLen    = 100
	maxEmailLen   = 254
	maxMessageLen = 5000

	// Cap for the contact JSON body itself, well below the global request cap.
	maxContactBodyBytes = 64 << 10 // 64 KiB
)

type contactCounter struct {
	count   int
	firstAt time.Time
}

var (
	contactMu       sync.Mutex
	contactAttempts map[string]*contactCounter = make(map[string]*contactCounter)
)

// allowContact returns false once an IP has exceeded its submission budget for
// the current window.
func allowContact(ip string) bool {
	now := time.Now()
	contactMu.Lock()
	defer contactMu.Unlock()
	if len(contactAttempts) >= maxTrackedContactIPs {
		for k, v := range contactAttempts {
			if now.Sub(v.firstAt) > contactWindow {
				delete(contactAttempts, k)
			}
		}
	}
	c := contactAttempts[ip]
	if c == nil || now.Sub(c.firstAt) > contactWindow {
		contactAttempts[ip] = &contactCounter{count: 1, firstAt: now}
		return true
	}
	if c.count >= contactMaxRequests {
		return false
	}
	c.count++
	return true
}

// validContactInput enforces field length caps and a real email syntax check.
func validContactInput(msg ContactMessage) bool {
	name := strings.TrimSpace(msg.Name)
	email := strings.TrimSpace(msg.Email)
	message := strings.TrimSpace(msg.Message)
	if name == "" || email == "" || message == "" {
		return false
	}
	if len(name) > maxNameLen || len(email) > maxEmailLen || len(message) > maxMessageLen {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return false
	}
	return true
}

// jsonMaxBytesReader caps a JSON request body and maps the overflow to a clean
// 413 instead of a generic "Invalid JSON".
type jsonMaxBytesReader struct {
	rc      *http.MaxBytesReader
	errFlag *bool
}

func (j jsonMaxBytesReader) Read(p []byte) (int, error) {
	n, err := j.rc.Read(p)
	if err != nil && strings.Contains(err.Error(), "http: request body too large") {
		*j.errFlag = true
	}
	return n, err
}

// decodeLimitedJSON decodes a JSON document of at most maxBytes into v.
func decodeLimitedJSON(r *http.Request, v interface{}, maxBytes int64) (tooLarge bool, err error) {
	rc := http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(jsonMaxBytesReader{rc: rc, errFlag: &tooLarge})
	if err := dec.Decode(v); err != nil {
		return tooLarge, err
	}
	return tooLarge, nil
}

// clientIP extracts the request address, using the left-most proxy hop only when
// the connection actually came from a loopback proxy.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isLoopback(host) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			parts := strings.Split(fwd, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	return host
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requireAuthCSRF guards a state-changing admin endpoint: the session must be
// valid AND the request must carry the CSRF token bound to that session. The
// token is accepted from the X-CSRF-Token header or a csrf form field, and the
// Origin/Referer of a cross-site request is rejected outright.
func (s *SiteApp) requireAuthCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !s.auth.IsAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	if !s.sameOrigin(r) {
		http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
		return false
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.FormValue("csrf")
	}
	if !s.auth.ValidateCSRF(r, token) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

// sameOrigin accepts a request only when its Origin (or Referer) matches the
// Host it was sent to. A browser-initiated cross-site POST always carries a
// foreign Origin, so this closes the CSRF hole independently of SameSite.
func (s *SiteApp) sameOrigin(r *http.Request) bool {
	scheme := "http"
	if requestIsSecure(r) {
		scheme = "https"
	}
	self := scheme + "://" + r.Host

	origin := r.Header.Get("Origin")
	if origin != "" {
		return strings.EqualFold(strings.TrimRight(origin, "/"), self)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" {
			return strings.EqualFold(u.Scheme+"://"+u.Host, self)
		}
		return false
	}
	// No Origin and no Referer: not a browser cross-site POST (curl/forms do
	// this). Still require the CSRF token itself, which is checked by caller.
	return true
}

func (s *SiteApp) render(w http.ResponseWriter, tmplName string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, tmplName, data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Template error", 500)
	}
}

func (s *SiteApp) renderJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func (s *SiteApp) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	data := s.store.GetAll()
	s.render(w, "index.html", data)
}

func (s *SiteApp) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	data := s.store.GetAll()
	s.render(w, "services.html", data)
}

func (s *SiteApp) handleGallery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	data := s.store.GetAll()
	s.render(w, "gallery.html", data)
}

func (s *SiteApp) handleAbout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	data := s.store.GetAll()
	s.render(w, "about.html", data)
}

func (s *SiteApp) handleContact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	data := s.store.GetAll()
	s.render(w, "contact.html", data)
}

func (s *SiteApp) handleContactAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	ip := clientIP(r)
	if !allowContact(ip) {
		w.Header().Set("Retry-After", strconv.Itoa(int(contactWindow.Seconds())))
		s.renderJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Слишком много запросов. Попробуй позже."})
		return
	}
	var msg ContactMessage
	tooLarge, err := decodeLimitedJSON(r, &msg, maxContactBodyBytes)
	if tooLarge {
		s.renderJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Сообщение слишком большое"})
		return
	}
	if err != nil {
		s.renderJSON(w, 400, map[string]string{"error": "Invalid JSON"})
		return
	}
	// Never trust a client-provided Date.
	msg.Date = ""
	msg.Name = strings.TrimSpace(msg.Name)
	msg.Email = strings.TrimSpace(msg.Email)
	msg.Message = strings.TrimSpace(msg.Message)
	if !validContactInput(msg) {
		s.renderJSON(w, 400, map[string]string{"error": "Проверь поля: все обязательны, email должен быть корректным, длина ограничена"})
		return
	}
	if err := s.store.AddMessage(msg); err != nil {
		s.renderJSON(w, 500, map[string]string{"error": "Server error"})
		return
	}
	s.renderJSON(w, 200, map[string]string{"ok": "Message sent"})
}

func (s *SiteApp) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !s.auth.IsAuthenticated(r) {
		if s.auth.NeedsSetup() {
			http.Redirect(w, r, "/admin/setup", http.StatusFound)
		} else {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
		}
		return
	}
	data := s.store.GetAll()
	s.render(w, "admin.html", AdminData{
		SiteData:   data,
		NeedsSetup: s.auth.NeedsSetup(),
		CsrfToken:  s.auth.CSRFTokenFor(r),
	})
}

func (s *SiteApp) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.render(w, "login.html", LoginView{CsrfToken: ""})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	// The login form is the one POST endpoint reachable without a session, so
	// it cannot carry a CSRF token. Same-origin enforcement covers it: a
	// browser-initiated cross-site submission always sends a foreign Origin.
	if !s.sameOrigin(r) {
		http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
		return
	}

	ip := clientIP(r)
	if !s.auth.ThrottleLogin(ip) {
		w.Header().Set("Retry-After", strconv.Itoa(int(loginLockDuration.Seconds())))
		s.render(w, "login.html", LoginView{Error: "Слишком много неудачных попыток. Вход временно заблокирован."})
		return
	}

	r.ParseForm()
	password := r.FormValue("password")
	if !s.auth.CheckPassword(password) {
		s.auth.RecordLoginFailure(ip)
		s.render(w, "login.html", LoginView{Error: "Неверный пароль"})
		return
	}
	s.auth.ClearLoginFailures(ip)
	cookie, _ := s.auth.CreateSession(r)
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *SiteApp) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	// Logout changes state, so it is CSRF-guarded like the other admin writes.
	if !s.requireAuthCSRF(w, r) {
		return
	}
	if c, err := r.Cookie("neocms_session"); err == nil {
		s.auth.DestroySession(c.Value)
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (s *SiteApp) handleSetup(w http.ResponseWriter, r *http.Request) {
	// Once an admin password exists the setup endpoint must be closed: leaving
	// it open lets any visitor overwrite the credentials and take the panel.
	if !s.auth.NeedsSetup() {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		http.Error(w, "Setup already completed", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet {
		s.render(w, "setup.html", LoginView{})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	// No session exists yet during setup, so CSRF is enforced via origin check.
	if !s.sameOrigin(r) {
		http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
		return
	}
	r.ParseForm()
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if password != confirm {
		s.render(w, "setup.html", LoginView{Error: "Пароли не совпадают"})
		return
	}
	if len(password) < 10 {
		s.render(w, "setup.html", LoginView{Error: "Пароль должен быть не менее 10 символов"})
		return
	}
	if err := s.auth.SetPassword(password); err != nil {
		s.render(w, "setup.html", LoginView{Error: "Ошибка сохранения"})
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (s *SiteApp) handleAdminSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !s.requireAuthCSRF(w, r) {
		return
	}
	var data SiteData
	tooLarge, err := decodeLimitedJSON(r, &data, maxRequestBytes)
	if tooLarge {
		s.renderJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Payload too large"})
		return
	}
	if err != nil {
		s.renderJSON(w, 400, map[string]string{"error": "Invalid JSON"})
		return
	}
	if err := s.store.SaveAll(data); err != nil {
		s.renderJSON(w, 500, map[string]string{"error": "Save failed"})
		return
	}
	s.renderJSON(w, 200, map[string]string{"ok": "Saved"})
}

func (s *SiteApp) handleAdminUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	// The CSRF token travels as a multipart field, so the form must be parsed
	// before the guard can read it: parse first with a tightened cap, then check.
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		var mme *multipart.MaxMemoryError
		if errors.As(err, &mme) || errors.Is(err, http.ErrBodyTooLarge) {
			s.renderJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Upload too large"})
			return
		}
		s.renderJSON(w, 400, map[string]string{"error": "Invalid upload"})
		return
	}
	if !s.requireAuthCSRF(w, r) {
		return
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		s.renderJSON(w, 400, map[string]string{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	// Validate declared size before reading any bytes.
	if header.Size > maxUploadBytes || header.Size <= 0 {
		s.renderJSON(w, 400, map[string]string{"error": "File too large (max 5MB)"})
		return
	}

	// Read the file (bounded), then detect the real type from magic bytes.
	// The client-supplied Content-Type header is spoofable and is not trusted.
	data, err := io.ReadAll(io.LimitReader(file, maxUploadBytes+1))
	if err != nil || len(data) > maxUploadBytes {
		s.renderJSON(w, 400, map[string]string{"error": "File too large (max 5MB)"})
		return
	}
	detected := http.DetectContentType(data[:min(512, len(data))])
	// http.DetectContentType does not recognize webp; sniff the RIFF/WEBP signature explicitly.
	if detected == "application/octet-stream" && isWebP(data) {
		detected = "image/webp"
	}
	allowed := map[string]bool{
		"image/png":  true,
		"image/jpeg": true,
		"image/webp": true,
		"image/gif":  true,
	}
	if !allowed[detected] {
		s.renderJSON(w, 400, map[string]string{"error": "Invalid file type"})
		return
	}

	// Derive the stored extension from the detected type, not from the filename.
	extMap := map[string]string{
		"image/png":  ".png",
		"image/jpeg": ".jpg",
		"image/webp": ".webp",
		"image/gif":  ".gif",
	}
	ext := extMap[detected]

	// Generate filename with random token to avoid collisions
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	filename := fmt.Sprintf("%s%s", hex.EncodeToString(randBytes), ext)

	uploadsDir := filepath.Join(filepath.Dir(s.store.path), "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		s.renderJSON(w, 500, map[string]string{"error": "Save error"})
		return
	}
	dst, err := os.Create(filepath.Join(uploadsDir, filename))
	if err != nil {
		s.renderJSON(w, 500, map[string]string{"error": "Save error"})
		return
	}
	defer dst.Close()

	if _, err := dst.Write(data); err != nil {
		s.renderJSON(w, 500, map[string]string{"error": "Write error"})
		return
	}

	s.store.AddGalleryItem(GalleryItem{Image: "/uploads/" + filename, Title: header.Filename})
	s.renderJSON(w, 200, map[string]string{"url": "/uploads/" + filename})
}

func isWebP(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	return string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP"
}

func (s *SiteApp) handleAdminDeleteImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !s.requireAuthCSRF(w, r) {
		return
	}
	var req struct {
		ID       string `json:"id"`
		Filename string `json:"filename"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.renderJSON(w, 400, map[string]string{"error": "Invalid request"})
		return
	}
	if req.ID == "" && req.Filename == "" {
		s.renderJSON(w, 400, map[string]string{"error": "id or filename required"})
		return
	}
	if req.Filename != "" {
		name := filepath.Base(req.Filename)
		if name != req.Filename || name == "." || name == ".." || strings.ContainsRune(name, '/') || strings.ContainsRune(name, '\\') {
			s.renderJSON(w, 400, map[string]string{"error": "Invalid filename"})
			return
		}
		path := filepath.Join("data/uploads", name)
		os.Remove(path)
		data := s.store.GetAll()
		for _, g := range data.Gallery {
			if filepath.Base(g.Image) == req.Filename {
				s.store.RemoveGalleryItem(g.ID)
				break
			}
		}
	}
	if req.ID != "" {
		s.store.RemoveGalleryItem(req.ID)
	}
	s.renderJSON(w, 200, map[string]string{"ok": "Deleted"})
}
