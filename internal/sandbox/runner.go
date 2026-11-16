package sandbox

import (
	"strings"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

type agent struct {
	harness.Harness
}

// EgressHosts is empty so only the host services explicitly granted to this run are reachable.
func (*agent) EgressHosts() []string { return nil }

// failures keeps the errors a run reports among its events. Codex exec --json reports why it stopped only there.
type failures []string

func (f *failures) keep(e harness.Event) {
	if e.Kind != harness.KindError || e.Text == "" {
		return
	}
	const maxMessages, maxBytes = 16, 4096
	if len(*f) == maxMessages {
		*f = (*f)[:copy(*f, (*f)[1:])]
	}
	*f = append(*f, strings.Clone(strings.ToValidUTF8(e.Text[max(0, len(e.Text)-maxBytes):], "")))
}

// runner grants the public-read service only to the online reader.
func (r *Reader) runner(state, source, token, publicPort string, env []string) container.Runner {
	ports := append([]string(nil), r.server.HostPorts...)
	if publicPort != "" {
		ports = append(ports, publicPort)
	}
	return container.Runner{
		Runtime:  r.runtime,
		Image:    r.image,
		StateDir: state,
		Mounts:   []container.Mount{{Host: source, Container: container.WorkMount + "/" + srcDir, ReadOnly: true}},
		// Codex's SQLite state crashes it with SIGBUS on a state directory bind-mounted by Docker Desktop.
		Env:               append(env, r.backend.keyEnv, "CODEX_SQLITE_HOME=/tmp/codex-sqlite"),
		OmitEnv:           []string{r.backend.keyEnv, "CLAUDE_CODE_OAUTH_TOKEN", "CODEX_API_KEY"},
		ProcessEnv:        []string{r.backend.keyEnv + "=" + token},
		Hardened:          true,
		IsolateHost:       true,
		Sidecar:           container.SidecarConfig{APIPort: r.server.APIPort, HostPorts: ports},
		ReadOnlyWorkspace: true,
		Memory:            "2g",
		CPUs:              "2",
		PIDsLimit:         256,
		FileSizeLimit:     64 << 20,
	}
}
