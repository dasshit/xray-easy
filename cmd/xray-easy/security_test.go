package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlPlaneMiddlewareSetsSecurityAndCacheHeaders(t *testing.T) {
	reached := false
	handler := controlPlaneMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !reached || response.Code != http.StatusNoContent {
		t.Fatalf("request was not passed through: reached=%v status=%d", reached, response.Code)
	}
	for header, want := range map[string]string{
		"Content-Security-Policy":      "default-src 'self'",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), payment=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store, private",
	} {
		if got := response.Header().Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want to contain %q", header, got, want)
		}
	}
}

func TestSetSecurityHeadersEnablesHSTSForHTTPSRequests(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://localhost:8080/", nil)
	response := httptest.NewRecorder()
	setSecurityHeaders(response, request)
	if got := response.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("HSTS header = %q", got)
	}
}

func TestControlPlaneMiddlewareRejectsCrossOriginMutation(t *testing.T) {
	called := false
	handler := controlPlaneMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/logout", nil)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("cross-origin mutation status=%d called=%v body=%s", response.Code, called, response.Body.String())
	}
}

func TestControlPlaneMiddlewareAllowsMatchingOriginAndOperationalRequests(t *testing.T) {
	for _, test := range []struct {
		name      string
		origin    string
		referer   string
		fetchSite string
	}{
		{name: "matching origin", origin: "http://localhost:8080"},
		{name: "matching referer", referer: "http://localhost:8080/dashboard"},
		{name: "no browser metadata"},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := controlPlaneMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }))
			request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/logout", nil)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.referer != "" {
				request.Header.Set("Referer", test.referer)
			}
			if test.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || !called {
				t.Fatalf("matching request status=%d called=%v", response.Code, called)
			}
		})
	}

	called := false
	handler := controlPlaneMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/logout", nil)
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || called {
		t.Fatalf("cross-site fetch status=%d called=%v", response.Code, called)
	}
}

func TestControlPlaneMiddlewareCapsRequestBody(t *testing.T) {
	handler := controlPlaneMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Error("handler read an oversized request without an error")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", strings.NewReader(strings.Repeat("x", maxHTTPRequestBody+1)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("oversized body reached handler with status %d", response.Code)
	}
}

func TestSecureSessionCookieIsOptInForSSHAndEnabledForHTTPS(t *testing.T) {
	t.Setenv("XRAY_EASY_SECURE_COOKIES", "false")
	httpRequest := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/login", nil)
	if secureSessionCookie(httpRequest) {
		t.Fatal("HTTP-over-SSH request unexpectedly requested a Secure cookie")
	}
	httpsRequest := httptest.NewRequest(http.MethodPost, "https://localhost:8080/api/auth/login", nil)
	httpsRequest.TLS = &tls.ConnectionState{}
	if !secureSessionCookie(httpsRequest) {
		t.Fatal("TLS request did not request a Secure cookie")
	}
	t.Setenv("XRAY_EASY_SECURE_COOKIES", "true")
	if !secureSessionCookie(httpRequest) {
		t.Fatal("explicit secure-cookie opt-in was ignored")
	}
}

func TestBrowserOriginParsingAndTrustedProxyScheme(t *testing.T) {
	t.Setenv("XRAY_EASY_TRUST_PROXY", "true")
	request := httptest.NewRequest(http.MethodPost, "http://[2001:db8::1]/api/clients", nil)
	request.Host = "[2001:db8::1]"
	request.Header.Set("X-Forwarded-Proto", "https, http")
	if got := requestScheme(request); got != "https" {
		t.Fatalf("trusted forwarded scheme = %q, want https", got)
	}
	if !sameOriginURL(request, "HTTPS://[2001:DB8::1]:443/dashboard", true) {
		t.Fatal("matching IPv6 origin with default TLS port was rejected")
	}
	if sameOriginURL(request, "https://[2001:db8::1]:443/dashboard", false) {
		t.Fatal("Origin header unexpectedly allowed a path")
	}

	for _, raw := range []string{
		"not a URL", "//[2001:db8::1]", "https://user@[2001:db8::1]",
		"https://[2001:db8::1]?query=1", "https://[2001:db8::1]#fragment",
		"https://[2001:db8::1]:bad", "http://[2001:db8::1]",
	} {
		if sameOriginURL(request, raw, true) {
			t.Errorf("sameOriginURL accepted %q", raw)
		}
	}

	request.Header.Set("X-Forwarded-Proto", "http, https")
	if got := requestScheme(request); got != "http" {
		t.Fatalf("first forwarded scheme = %q, want http", got)
	}
	t.Setenv("XRAY_EASY_TRUST_PROXY", "false")
	request.Header.Set("X-Forwarded-Proto", "https")
	if got := requestScheme(request); got != "http" {
		t.Fatalf("untrusted forwarded scheme = %q, want http", got)
	}
}

func TestCanonicalHostPortNormalizesHostsAndDefaultPorts(t *testing.T) {
	for _, test := range []struct {
		host, scheme, want string
	}{
		{host: " Example.COM ", scheme: "http", want: "example.com:80"},
		{host: "example.com:8443", scheme: "https", want: "example.com:8443"},
		{host: "[2001:DB8::2]", scheme: "https", want: "[2001:db8::2]:443"},
		{host: "[2001:DB8::2]:9443", scheme: "http", want: "[2001:db8::2]:9443"},
		{host: "not a host", scheme: "http", want: ""},
	} {
		if got := canonicalHostPort(test.host, test.scheme); got != test.want {
			t.Errorf("canonicalHostPort(%q, %q) = %q, want %q", test.host, test.scheme, got, test.want)
		}
	}
}

func TestRejectedOriginErrorMessage(t *testing.T) {
	if got := (errOriginRejected{}).Error(); got != "request origin is not allowed" {
		t.Fatalf("origin rejection message = %q", got)
	}
}

func TestLogoutAcceptsPostOnly(t *testing.T) {
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/auth/logout", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status = %d", got)
	}
}
