package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

const maxHTTPRequestBody = 4 << 20

// requestLimit is kept as a small reusable body-limit wrapper for callers that
// construct the mux directly in tests and operational tooling.
func requestLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxHTTPRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// controlPlaneMiddleware is the browser-facing HTTP boundary. It deliberately
// keeps the default SSH-forwarded HTTP deployment working while adding
// defense-in-depth for browsers and reverse-proxy deployments.
func controlPlaneMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, private")
			w.Header().Set("Pragma", "no-cache")
		}
		if err := validateBrowserOrigin(r); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{"code": "origin_rejected", "error": "request origin is not allowed"})
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxHTTPRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Origin, Referer, Sec-Fetch-Site, X-Forwarded-Proto")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	if requestScheme(r) == "https" {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
}

// validateBrowserOrigin rejects explicit cross-site browser metadata while
// allowing non-browser operational clients that omit Origin and Referer.
func validateBrowserOrigin(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return errOriginRejected{}
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		if !sameOriginURL(r, origin, false) {
			return errOriginRejected{}
		}
		return nil
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" && !sameOriginURL(r, referer, true) {
		return errOriginRejected{}
	}
	return nil
}

type errOriginRejected struct{}

func (errOriginRejected) Error() string { return "request origin is not allowed" }

func sameOriginURL(r *http.Request, raw string, allowPath bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if !allowPath && parsed.Path != "" {
		return false
	}
	scheme := requestScheme(r)
	return strings.EqualFold(parsed.Scheme, scheme) && canonicalHostPort(parsed.Host, scheme) == canonicalHostPort(r.Host, scheme)
}

func canonicalHostPort(host, scheme string) string {
	host = strings.TrimSpace(host)
	parsed, err := url.Parse("//" + host)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(parsed.Hostname()), port)
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if envBool("XRAY_EASY_TRUST_PROXY") {
		forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
		if strings.EqualFold(forwarded, "https") {
			return "https"
		}
		if strings.EqualFold(forwarded, "http") {
			return "http"
		}
	}
	return "http"
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(envOr(name, ""))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func secureSessionCookie(r *http.Request) bool {
	return requestScheme(r) == "https" || envBool("XRAY_EASY_SECURE_COOKIES")
}
