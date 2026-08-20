package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxGateBody bounds how much of a request the gate will buffer to find the
// tool name. MCP tool calls are small; anything larger is not a call this gate
// needs to inspect, and buffering it would be a memory amplification.
const maxGateBody = 1 << 20

// ToolScopes maps a tool name to the scope it requires.
//
// Only the privileged tools appear. Anything absent is covered by the baseline
// scope the middleware already enforced, so a new read-only tool needs no entry
// and cannot accidentally be left unprotected — whereas a new *raw* tool that
// someone forgets to add here would be exposed, which is why the test asserting
// every raw/admin tool has an entry lives next to the tool registration.
type ToolScopes map[string]string

// ScopeGate enforces per-tool scopes at the HTTP layer.
//
// It exists because design §5.4 requires a real 403 with a WWW-Authenticate
// scope challenge, so the client can step up in one round trip. A tool handler
// cannot produce that: by the time it runs, the JSON-RPC response shape is
// fixed and headers are committed. So the gate reads the tool name out of the
// request body before dispatch.
//
// The body is buffered and replaced, which is the cost of doing this properly.
// It is bounded, and it only happens for POST requests that look like tool
// calls.
func ScopeGate(scopes ToolScopes, resourceMetadataURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || len(scopes) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, maxGateBody))
			if err != nil {
				http.Error(w, "could not read request body", http.StatusBadRequest)
				return
			}
			_ = r.Body.Close()
			// Whatever happens next, downstream must see the whole body.
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))

			name := toolNameFromBody(body)
			if name == "" {
				next.ServeHTTP(w, r)
				return
			}
			required, ok := scopes[name]
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if HasScope(r.Context(), required) {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("WWW-Authenticate", ScopeChallenge(required, resourceMetadataURL))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "insufficient_scope",
				"error_description": fmt.Sprintf(
					"the %s tool requires the %s scope; request it and retry", name, required),
				"scope": required,
			})
		})
	}
}

// toolNameFromBody extracts params.name from a tools/call request.
//
// It is deliberately forgiving: anything it cannot parse returns "", which lets
// the request through to be rejected by the protocol layer that actually
// understands it. A gate that rejected malformed JSON itself would be a second,
// divergent parser of the wire protocol.
func toolNameFromBody(body []byte) string {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		// Batches are arrays. A batch mixing privileged and unprivileged calls
		// cannot be answered with one 403, so it is left to the protocol layer;
		// the per-tool check in the handler is the backstop there.
		return ""
	}
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return ""
	}
	if req.Method != "tools/call" {
		return ""
	}
	return strings.TrimSpace(req.Params.Name)
}
