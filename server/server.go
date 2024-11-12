package server

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"regexp"
)

//go:embed views/*
var viewsFs embed.FS

type publicError struct {
	err error
	msg string
}

func (se publicError) Error() string {
	return se.msg
}

// Server represents a server
type Server struct {
	mux        *http.ServeMux
	log        *slog.Logger
	tmpl       *template.Template
	currentRid uint
}

func (s *Server) getRequestId() uint {
	curr := s.currentRid
	s.currentRid = s.currentRid + 1
	return curr
}

// Run runs the server and returns the server
func (s *Server) Run(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

// New creates and returns a new server
func New() *Server {
	tmpl, err := template.ParseFS(viewsFs, "views/error.html")
	if err != nil {
		panic(err)
	}

	server := &Server{
		mux:  http.NewServeMux(),
		log:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
		tmpl: tmpl,
	}

	server.mux.Handle("GET /", wrapHandler(server, handleGet))

	return server
}

// handlerWithError is a normal HTTP handler that can return an error
type handlerWithError = func(w http.ResponseWriter, r *http.Request) error

type protectDetails struct {
	Enabled  bool              `json:"enabled"`
	Accounts map[string]string `json:"accounts"`
}

// wrapHandler turns a handlerWithError into a http.Handler
func wrapHandler(s *Server, handler handlerWithError) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := s.getRequestId()

		s.log.Info("Handling Request.", "host", r.Host, "path", r.URL.Path, "rid", rid)
		err := handler(w, r)
		if err == nil {
			return
		}

		errText := ""
		publicErr, ok := err.(publicError)
		if ok {
			// it's a public error
			errText = publicErr.msg
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			s.tmpl.Execute(w, map[string]interface{}{
				"errorText": errText,
			})
		} else {
			// it's an internal server error
			errText = err.Error()
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			s.tmpl.Execute(w, map[string]interface{}{
				"errorText": "Internal Server Error",
			})
		}

		s.log.Error("Encountered error when handling request.", "url", r.URL.String(), "err", errText, "isPublic", ok, "host", r.Host, "rid", rid)
	})
}

var hostRegexp = regexp.MustCompile(`^(?:https?:\/\/)?(?:www\.)?([^:\\\/]+)`)

// handleGet handles requests to the different pages
func handleGet(w http.ResponseWriter, r *http.Request) error {
	hostnameBytes := hostRegexp.Find([]byte(r.Host))
	if hostnameBytes == nil {
		return publicError{fmt.Errorf("failed to parse header: \"%s\"", r.Host), "Failed to parse header: " + string(r.Host)}
	}
	hostname := string(hostnameBytes)

	if len(hostname) < 1 {
		return publicError{errors.New("hostname has length < 1"), "Invalid hostname. (length < 1)"}
	}

	folderPath := path.Join(os.Getenv("PAGED_BASE_PATH"), hostname)
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		return publicError{err, "No Paged Site was found at this hostname."}
	}

	if r.URL.Path == "/" {
		r.URL.Path = "/index.html"
	}

	var protect protectDetails

	protectPath := path.Join(folderPath, "paged.json")
	if f, err := os.Open(protectPath); err == nil {
		by, err := io.ReadAll(f)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(by, &protect); err != nil {
			return publicError{err, "Malformed json: " + err.Error()}
		}
	}

	if protect.Enabled {
		user, pass, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+hostname+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil
		}

		userPassword, ok := protect.Accounts[user]
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+hostname+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil
		}

		hash := sha256.New()
		hash.Write([]byte(pass))
		passHash := hash.Sum(nil)
		if fmt.Sprintf("%x", passHash) != userPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+hostname+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return nil
		}
	}

	filePath := path.Join(folderPath, r.URL.Path)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return publicError{err, "404, file not found."}
	}

	f, err := os.Open(filePath)
	if err != nil {
		return publicError{err, "404, file not found."}
	}

	defer f.Close()

	bytes, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	mime := http.DetectContentType(bytes)

	// the mime detector works fine for binary types, but sometimes we need to use the file extension
	ext := path.Ext(filePath)
	switch ext {
	case ".css":
		mime = "text/css"
	case ".mjs":
		fallthrough
	case ".js":
		mime = "text/javascript"
	case ".json":
		mime = "application/json"
	}

	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "public, max-age=1800") // cache for 30 mins
	w.Write(bytes)

	return nil
}
