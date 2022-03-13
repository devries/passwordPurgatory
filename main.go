package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("/", NewQueryHandler())

	logHandler := loggingHandler(mux)

	// Just use port 8080 without SSL
	portString := os.Getenv("PORT")
	if portString == "" {
		portString = "8080"
	}
	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", portString),
		Handler: logHandler,
	}
	log.Printf("Starting on port %s\n", portString)
	log.Fatal(server.ListenAndServe())
}

type PasswordTest func(password string) error

type QueryHandler []PasswordTest

func NewQueryHandler() QueryHandler {
	ptest := []PasswordTest{
		func(password string) error {
			if password == "" {
				return errors.New("No password was provided")
			}
			return nil
		},
		func(password string) error {
			if utf8.RuneCountInString(password) < 12 {
				return errors.New("Password must be at least 12 characters long")
			}
			return nil
		},
		func(password string) error {
			if utf8.RuneCountInString(password) > 20 {
				return errors.New("Password must be less than 21 characters long")
			}
			return nil
		},
		regexpMatcher(`[0-9]`, "Password must contain at least 1 number"),
		regexpMatcher(`[a-z]`, "Password must contain at least 1 lowercase letter"),
		regexpMatcher(`[A-Z]`, "Password must contain at least 1 uppercase letter"),
		regexpMatcher(`!|"|#|\$|%|&|'|\*|\+|\?`, "Password must contain at least one of the following special characters: !, \", #, $, %, &, ', +, or ?"),
		func(password string) error {
			if strings.ContainsAny(password, "^()[]@") {
				return errors.New("Password must not contain any of the following special characters: ^, (, ), [, ], or @")
			}
			return nil
		},
		regexpMatcher("[\u0370-\u03ff\u1f00-\u1fff]", "Password must contain at least 1 greek letter"),
		regexpMatcher(`:‑\)|:\)|:\-\]|:\]|:>|:\-\}|:\}|:o\)\)|:\^\)|=\]|=\)|:\]|:\->|:>|8\-\)|:\-\}|:\}|:o\)|:\^\)|=\]|=\)|:‑D|:D|B\^D|:‑\(|:\(|:‑<|:<|:‑\[|:\[|:\-\|\||>:\[|:\{|:\(|;\(|:\'‑\(|:\'\(|:=\(|:\'‑\)|:\'\)|:"D|:‑O|:O|:‑o|:o|:\-0|>:O|>:3|;‑\)|;\)|;‑\]|;\^\)|:‑P|:\-\/|:\/|:‑\.|>:|>:\/|:|:‑\||:\||>:‑\)|>:\)|\}:‑\)|>;‑\)|>;\)|>:3|\|;‑\)|:‑J|<:‑\||~:>`, "Password must contain at least 1 emoticon"),
	}

	return QueryHandler(ptest)
}

func (q QueryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	password := query.Get("password")
	w.Header().Set("Access-Control-Allow-Origin", "*") // set CORS

	for _, f := range q {
		err := f(password)
		if err != nil {
			jr := JsonMessage{err.Error()}
			jr.WriteResponse(w, 200)
			return
		}
	}
	catchAll := JsonMessage{"This password has already been used by another user"}
	catchAll.WriteResponse(w, 200)
}

func regexpMatcher(expression string, message string) PasswordTest {
	re := regexp.MustCompile(expression)
	return func(password string) error {
		if !re.MatchString(password) {
			return errors.New(message)
		}
		return nil
	}
}

type JsonMessage struct {
	Message string `json:"message"`
}

func (jmess JsonMessage) WriteResponse(w http.ResponseWriter, code int) {
	w.Header().Set("Concent-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(jmess)
}

type statusRecorder struct {
	http.ResponseWriter
	status    int
	byteCount int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *statusRecorder) Write(p []byte) (int, error) {
	bc, err := rec.ResponseWriter.Write(p)
	rec.byteCount += bc

	return bc, err
}

func loggingHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec := statusRecorder{w, 200, 0}
		next.ServeHTTP(&rec, req)
		remoteAddr := req.Header.Get("X-Forwarded-For")
		if remoteAddr == "" {
			remoteAddr = req.RemoteAddr
		}
		ua := req.Header.Get("User-Agent")

		log.Printf("%s - \"%s %s %s\" (%s) %d %d \"%s\"", remoteAddr, req.Method, req.URL.Path, req.Proto, req.Host, rec.status, rec.byteCount, ua)
	})
}

func redirectTLS(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	u := r.URL
	u.Scheme = "https"
	u.Host = host
	remoteAddr := r.Header.Get("X-Forwarded-For")
	if remoteAddr == "" {
		remoteAddr = r.RemoteAddr
	}
	log.Printf("%s - Redirect to HTTPS (%s)", remoteAddr, u.String())
	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
}
