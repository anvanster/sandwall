// Command otlpsink is a minimal OTLP/HTTP logs receiver for e2e tests. It
// writes one JSON line per log record to -out:
//
//	{"event_name": ..., "severity": ..., "body": ..., "attrs": {...},
//	 "service": ..., "authorization": ...}
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

type line struct {
	EventName     string            `json:"event_name"`
	Severity      string            `json:"severity"`
	Body          string            `json:"body"`
	Attrs         map[string]string `json:"attrs"`
	Service       string            `json:"service"`
	Authorization string            `json:"authorization"`
}

func value(v *commonpb.AnyValue) string {
	switch x := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_ArrayValue:
		b, _ := json.Marshal(x.ArrayValue.Values)
		return string(b)
	}
	return ""
}

func main() {
	addr := flag.String("listen", "127.0.0.1:4318", "listen address")
	out := flag.String("out", "", "output file")
	flag.Parse()
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	http.HandleFunc("POST /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			body = zr
		}
		data, _ := io.ReadAll(body)
		var req collogs.ExportLogsServiceRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, rl := range req.ResourceLogs {
			service := ""
			for _, a := range rl.Resource.GetAttributes() {
				if a.Key == "service.name" {
					service = value(a.Value)
				}
			}
			for _, sl := range rl.ScopeLogs {
				for _, rec := range sl.LogRecords {
					l := line{EventName: rec.EventName, Severity: rec.SeverityText, Body: value(rec.Body),
						Attrs: map[string]string{}, Service: service, Authorization: r.Header.Get("Authorization")}
					for _, a := range rec.Attributes {
						l.Attrs[a.Key] = value(a.Value)
					}
					b, _ := json.Marshal(l)
					f.Write(append(b, '\n'))
				}
			}
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	})
	log.Fatal(http.ListenAndServe(*addr, nil))
}
