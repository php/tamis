package sandbox

import (
	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

type agent struct {
	harness.Harness
}

// EgressHosts is empty so the egress proxy allows the model proxy and the request's hosts only, not the
// provider's own API.
func (*agent) EgressHosts() []string { return nil }

// failures keeps the errors a run reports among its events. Codex exec --json reports why it stopped only there.
type failures []string

func (f *failures) keep(e harness.Event) {
	if e.Kind == harness.KindError {
		*f = append(*f, e.Text)
	}
}

// runner keeps the agent on a network whose only way out is the egress proxy, allowing the model proxy and
// hosts.
func (r *Reader) runner(state, source, token string, hosts, env []string) container.Runner {
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
		Sidecar:           container.SidecarConfig{Allow: hosts, APIPort: r.server.APIPort, HostPorts: r.server.HostPorts},
		ReadOnlyWorkspace: true,
		Memory:            "2g",
		CPUs:              "2",
		PIDsLimit:         256,
		FileSizeLimit:     64 << 20,
	}
}
