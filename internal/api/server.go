//go:build linux

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"

	"github.com/anvanster/egressd/internal/daemon"
)

const maxBody = 1 << 20

// NewHandler routes API requests to the manager.
func NewHandler(mgr *daemon.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mgr.List())
	})
	mux.HandleFunc("POST /v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		var req CreateRequest
		if !readJSON(w, r, &req) {
			return
		}
		info, err := mgr.Create(r.Context(), req.ID, req.Mode, req.Policy)
		respond(w, http.StatusCreated, info, err)
	})
	mux.HandleFunc("GET /v1/sandboxes/{id}", func(w http.ResponseWriter, r *http.Request) {
		info, err := mgr.Get(r.PathValue("id"))
		respond(w, http.StatusOK, info, err)
	})
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", func(w http.ResponseWriter, r *http.Request) {
		err := mgr.Destroy(r.Context(), r.PathValue("id"))
		respond(w, http.StatusOK, map[string]string{"destroyed": r.PathValue("id")}, err)
	})
	mux.HandleFunc("PUT /v1/sandboxes/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		var req PolicyRequest
		if !readJSON(w, r, &req) {
			return
		}
		info, err := mgr.ApplyPolicy(r.Context(), r.PathValue("id"), req.Policy)
		respond(w, http.StatusOK, info, err)
	})
	mux.HandleFunc("POST /v1/nuke", func(w http.ResponseWriter, r *http.Request) {
		err := mgr.Nuke(r.Context())
		respond(w, http.StatusOK, map[string]bool{"nuked": true}, err)
	})
	return mux
}

// Serve listens on a root-only unix socket until ctx is cancelled.
func Serve(ctx context.Context, socket string, h http.Handler) error {
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: h}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = os.Remove(socket)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad request: " + err.Error()})
		return false
	}
	return true
}

func respond(w http.ResponseWriter, okStatus int, body any, err error) {
	switch {
	case err == nil:
		writeJSON(w, okStatus, body)
	case errors.Is(err, daemon.ErrNotFound):
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: err.Error()})
	case errors.Is(err, daemon.ErrExists):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: err.Error()})
	default:
		writeJSON(w, http.StatusUnprocessableEntity, ErrorResponse{Error: err.Error()})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
