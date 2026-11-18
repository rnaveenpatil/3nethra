# Trinetra Sandbox

The Trinetra sandbox is the hostile-execution boundary for URL and file investigations. It is designed around one rule: the investigated website, uploaded file, browser process and LLM request are untrusted. Security decisions are enforced by the Linux kernel, Docker, iptables, a filtering DNS resolver and resource limits, not by prompts.

## Architecture

```
main Trinetra agent
        |
        | authenticated JSON over loopback
        v
FastAPI sandbox manager (trusted host process)
        |
        | Docker API over /var/run/docker.sock
        v
per-session Docker bridge network
        |
        | iptables egress policy + filtering DNS + resource limits
        v
disposable worker container (untrusted content)
        |
        | /work tmpfs only
        v
Playwright / httpx / static analysis / optional ffprobe+ffmpeg
        |
        | evidence archive copied through Docker API
        v
safe tar extraction into a 0700 host directory
        |
        v
structured JSON evidence + bounded artifacts
```

The worker never receives the Docker socket, a host bind mount, the host home directory, host environment variables, SSH keys or host credentials. The manager removes the container, network, DNS socket and iptables rules when a session is terminated, expires or fails.

## Files

| File | Purpose |
| --- | --- |
| `manager.py` | FastAPI manager, lifecycle state machine, Docker runtime, evidence collection, authenticated API |
| `worker.py` | In-container investigation worker for URLs, files, browser automation and optional media analysis |
| `network_policy.py` | SSRF policy, reserved/private/metadata blocking, filtering DNS resolver, per-session iptables isolation |
| `security.py` | Container hardening helpers, safe tar extraction, evidence sanitization, bounded subprocess execution |
| `config.py` | Environment settings and hard validation |
| `protocol.py` | Request and response schemas |
| `docker/Dockerfile.worker` | Pinned Playwright worker image |
| `docker/seccomp-worker.json` | Seccomp deny profile for the worker |
| `docker/apparmor-worker` | Optional AppArmor profile |
| `docker/build.sh` | Build the worker image |
| `tests/` | Security and lifecycle tests |

## Security controls

### Filesystem isolation

- The worker root filesystem is read-only.
- `/tmp` and `/run` are writable tmpfs mounts owned by the unprivileged worker UID. `/work` is a fresh anonymous Docker volume used only for the task handshake and evidence; it is removed with the worker container.
- No host path is bind-mounted. Inputs are copied into `/work` through the Docker archive API, not from a host mount.
- Evidence is copied out through the Docker archive API and extracted with `security.safe_extract_tar`, which rejects absolute paths, `..` traversal, duplicate members, symlinks, hardlinks, devices, oversized archives and excessive file counts.
- The Docker socket, host home, SSH keys and host environment are never present in the worker.
- Each session gets a fresh writable work volume and a fresh network. Temporary inputs are deleted after startup; the anonymous work volume is removed with the container. Session evidence lives in a 0700 directory and is deleted on `DELETE /v1/sessions/{id}`, expiry, or manager shutdown.

### Network isolation

- Each session gets its own Docker bridge network with IPv6 disabled and inter-container communication disabled.
- The manager installs a per-session iptables chain for worker traffic:
  - Drop loopback, private, link-local, carrier-grade NAT, multicast, reserved, documentation, benchmarking and IPv4-mapped/NAT64/6to4/Teredo IPv6 ranges.
  - Explicitly drop cloud metadata endpoints, including `169.254.169.254`, `169.254.170.2` and `100.100.100.200`.
  - Allow only TCP 80 and 443 to public destinations.
  - Drop all other forwarded traffic.
  - Drop new inbound connections to the worker subnet.
- Host access is blocked with an INPUT chain: the worker may only reach the per-session filtering DNS port; every other destination on the host is dropped.
- DNS is directed to a filtered resolver on the host bridge gateway. The resolver:
  - Uses fixed public upstream resolvers.
  - Rejects queries for private/internal names.
  - Validates every A and AAAA answer.
  - Refuses answers containing any forbidden address.
  - Clamps TTLs and caches only validated answers.
- Even if DNS rebinding or a redirect returns a private address after validation, the packet destination is blocked by iptables. This is the authoritative control.
- No worker ports are published to the host or internet.
- The manager API authenticates every `/v1` request with `SANDBOX_API_TOKEN` and binds to loopback by default.

### Process isolation

- Worker runs as UID/GID 10001, never as root.
- `privileged=false`.
- All Linux capabilities are dropped (`cap_drop: ALL`, `cap_add: []`).
- `no-new-privileges` is enabled.
- CPU, memory, swap, process count, open files, shared memory and tmpfs limits are applied.
- A custom seccomp profile denies mount, module loading, BPF, perf events, io_uring, ptrace, userfaultfd, keyring, reboot, swap and related syscalls.
- An AppArmor profile is supported when loaded on the host. The manager adds `apparmor=trinetra-worker` only when `SANDBOX_APPARMOR_PROFILE` is set.
- The worker uses `--no-sandbox` for Chromium inside the disposable container. The container and kernel limits are the security boundary; a privileged browser sandbox is not exposed to the host.
- FFmpeg and ffprobe run only when explicitly requested, with CPU, address-space, file-size, process-count and wall-clock limits. Downloaded files and uploaded files are never executed.

### Lifecycle

1. `POST /v1/sessions` validates the request, stores the uploaded file in a 0700 host temp directory, writes a task file and allocates a session ID.
2. `POST /v1/sessions/{id}/investigate` creates a fresh network, installs the firewall and DNS policy, starts a fresh worker container and copies the task/input into its tmpfs.
3. The manager polls structured worker status and enforces its own wall-clock deadline in addition to worker/Docker limits.
4. Evidence is copied out, sanitized and stored. The worker container, network, DNS socket and iptables chains are destroyed.
5. `POST /v1/sessions/{id}/terminate` cancels and stops an investigation. `DELETE /v1/sessions/{id}` destroys evidence and the session record.
6. Expired sessions are swept periodically. On startup the manager removes orphaned sandbox containers and networks from a previous crash.

## Setup

Requirements:

- Linux with Docker
- Python 3.11 or newer
- `iptables` and `CAP_NET_ADMIN` (the manager normally runs as root or with systemd ambient capabilities)
- Access to the Docker socket (root or a user in the `docker` group)
- Optional: AppArmor enabled on the host

Build the worker image:

```bash
sudo sandbox/docker/build.sh trinetra-sandbox-worker:latest
```

Install manager dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r sandbox/requirements-manager.txt
```

Generate an API token:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Optional AppArmor:

```bash
sudo apparmor_parser -r sandbox/docker/apparmor-worker
export SANDBOX_APPARMOR_PROFILE=trinetra-worker
```

Run the manager:

```bash
export SANDBOX_API_TOKEN='replace-with-a-long-random-token'
export SANDBOX_WORKER_IMAGE='trinetra-sandbox-worker:latest'
sudo -E .venv/bin/uvicorn sandbox.manager:app --host 127.0.0.1 --port 8765 --workers 1
```

Always run exactly one manager process. Sessions are in-memory, and the manager owns per-session host firewall state. Do not expose the API beyond loopback without an additional authenticated TLS proxy. The manager has Docker socket access, which is equivalent to host root; treat it as a trusted control-plane component.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `SANDBOX_API_TOKEN` | none | Required, at least 32 characters |
| `SANDBOX_BIND_HOST` | `127.0.0.1` | Keep on loopback |
| `SANDBOX_BIND_PORT` | `8765` | Manager API port |
| `SANDBOX_DOCKER_URL` | `unix:///var/run/docker.sock` | Docker endpoint |
| `SANDBOX_DOCKER_RUNTIME` | none | Optional runtime such as `runsc` or `kata` |
| `SANDBOX_WORKER_IMAGE` | `trinetra-sandbox-worker:latest` | Built locally |
| `SANDBOX_SECCOMP_PROFILE` | `sandbox/docker/seccomp-worker.json` | Host path read by the manager and sent inline to Docker |
| `SANDBOX_APPARMOR_PROFILE` | none | Optional loaded AppArmor profile name |
| `SANDBOX_ENABLE_HOST_FIREWALL` | `true` | Must remain true for isolation |
| `SANDBOX_ALLOW_UNSAFE_NETWORK` | `false` | Explicit development bypass; never use for hostile content |
| `SANDBOX_DNS_UPSTREAMS` | `1.1.1.1,9.9.9.9` | Must be public IPs |
| `SANDBOX_DNS_PORT` | `15353` | Host-side filtered resolver port |
| `SANDBOX_SESSION_TTL_SECONDS` | `900` | Evidence/session lifetime |
| `SANDBOX_DEFAULT_TIMEOUT_SECONDS` | `120` | Default investigation timeout |
| `SANDBOX_MAX_TIMEOUT_SECONDS` | `300` | Upper bound |
| `SANDBOX_MAX_SESSIONS` | `4` | Concurrent live sessions |
| `SANDBOX_WORKER_CPUS` | `1.0` | CPU quota |
| `SANDBOX_WORKER_MEMORY_BYTES` | `1073741824` | Memory and swap limit |
| `SANDBOX_WORKER_PIDS` | `256` | PID limit |
| `SANDBOX_MAX_UPLOAD_BYTES` | `26214400` | Upload size |
| `SANDBOX_MAX_EVIDENCE_BYTES` | `67108864` | Evidence archive/JSON limit |
| `SANDBOX_MAX_ARTIFACT_BYTES` | `16777216` | Single artifact limit |
| `SANDBOX_MAX_ARTIFACTS` | `32` | Artifact count limit |
| `SANDBOX_MAX_LOG_BYTES` | `1048576` | Worker log cap |
| `SANDBOX_EVIDENCE_ROOT` | `/tmp/trinetra-evidence` | 0700 session directories |
| `SANDBOX_MANAGE_ORPHANS` | `true` | Remove orphan containers/networks on startup |

## API

All `/v1` endpoints require either:

```http
Authorization: Bearer <SANDBOX_API_TOKEN>
```

or:

```http
X-Sandbox-Token: <SANDBOX_API_TOKEN>
```

Create a URL session:

```bash
curl -sS -X POST http://127.0.0.1:8765/v1/sessions \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"url","url":"https://example.com/","options":{"take_screenshot":true}}'
```

Create a file session:

```bash
curl -sS -X POST http://127.0.0.1:8765/v1/sessions \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"kind\":\"file\",\"file\":{\"filename\":\"sample.bin\",\"content_base64\":\"$(base64 -w0 sample.bin)\"}}"
```

Start, monitor, and retrieve:

```bash
curl -sS -X POST http://127.0.0.1:8765/v1/sessions/$SESSION_ID/investigate \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN"

curl -sS http://127.0.0.1:8765/v1/sessions/$SESSION_ID \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN"

curl -sS http://127.0.0.1:8765/v1/sessions/$SESSION_ID/evidence \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN"

curl -sS -OJ http://127.0.0.1:8765/v1/sessions/$SESSION_ID/artifacts/screenshot.png \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN"

curl -sS -X POST http://127.0.0.1:8765/v1/sessions/$SESSION_ID/terminate \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN"

curl -sS -X DELETE http://127.0.0.1:8765/v1/sessions/$SESSION_ID \
  -H "Authorization: Bearer $SANDBOX_API_TOKEN"
```

Endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Minimal unauthenticated health check |
| `POST` | `/v1/sessions` | Create a URL or file session |
| `GET` | `/v1/sessions` | List known sessions |
| `GET` | `/v1/sessions/{id}` | Status, phase, progress and artifacts |
| `POST` | `/v1/sessions/{id}/investigate` | Start the worker |
| `GET` | `/v1/sessions/{id}/evidence` | Structured evidence after completion |
| `GET` | `/v1/sessions/{id}/logs` | Sanitized worker logs |
| `GET` | `/v1/sessions/{id}/artifacts` | Artifact metadata |
| `GET` | `/v1/sessions/{id}/artifacts/{name}` | Download an artifact as an attachment |
| `POST` | `/v1/sessions/{id}/terminate` | Stop a running investigation |
| `DELETE` | `/v1/sessions/{id}` | Destroy the session and evidence |

Session states: `created`, `running`, `completed`, `failed`, `timed_out`, `terminated`.

Evidence status is separate from the HTTP response: a completed investigation may report `"outcome": "blocked"` when the target was a private address, metadata endpoint, internal hostname or otherwise denied by policy. This is expected and is not a worker failure.

## Evidence and artifacts

Evidence is JSON with a stable top-level shape:

- `schema_version`, `status`, `outcome`, `session_id`, timestamps
- `target`, `dns`, `http`, `browser` for URL investigations
- `file` for file investigations
- `artifacts`, `warnings`, `errors`, `limits`, `engine`

URL evidence includes DNS answers, redirect chains, HTTP status/headers, sanitized TLS certificate metadata, browser responses, blocked requests, console messages, page metadata, script/resource URLs, forms, screenshot and bounded HTML capture. Authorization, cookie and secret-like headers/values are redacted. URL query values with sensitive names are redacted.

File evidence includes hashes, size, entropy, magic/type, strings, embedded URLs/IPs, executable header fields, PDF active-content indicators, archive listings without extraction, and optional media metadata/frame extraction. Files are never executed.

Artifacts are served as attachments with `X-Content-Type-Options: nosniff`, a restrictive CSP and `application/octet-stream` for anything not positively identified as a safe image or text file. HTML is always served as `text/plain`. Artifact names are validated and cannot escape the evidence directory.

## Tests

Unit and API security tests:

```bash
.venv/bin/pip install -r sandbox/requirements-dev.txt
.venv/bin/pytest sandbox/tests -q
```

Docker integration tests are opt-in because they require a built worker image, Docker access and `CAP_NET_ADMIN`:

```bash
sudo SANDBOX_WORKER_IMAGE=trinetra-sandbox-worker:latest \
  TRINETRA_RUN_DOCKER_TESTS=1 \
  .venv/bin/pytest sandbox/tests/test_docker_integration.py -q
```

The tests cover host file/tar escapes, private and metadata address blocking, redirects to private destinations, DNS answer validation, container hardening, resource limits, firewall egress rules, API authentication, lifecycle cleanup, evidence redaction and artifact path safety. The opt-in integration test starts a hardened probe container on a real sandbox network and verifies that metadata, loopback, private and host destinations are unreachable.

## Operational notes and limitations

- Egress is intentionally limited to TCP 80 and 443. Sites requiring other ports will fail and produce evidence of that failure.
- IPv6 is disabled on sandbox networks. If the host requires IPv6 egress, add equivalent ip6tables enforcement before enabling IPv6.
- The manager must run with `CAP_NET_ADMIN` and Docker socket access. Running without both fails closed unless `SANDBOX_ALLOW_UNSAFE_NETWORK=1` is explicitly set for development. Unsafe mode has no host firewall and uses Docker default DNS instead of the filtered resolver; use it only for local development with non-hostile content.
- AppArmor must be supported and loaded by the host. If the profile is not loaded, the manager fails to start the worker rather than silently dropping the control.
- Playwright browsers are disposable but are not lightweight. Size memory and CPU limits for the expected pages.
- Downloads are stored only when `allow_downloads` is requested; they are never opened or executed. The `/work` volume is ephemeral and destroyed with the container. Media probing and frame extraction require `analyze_media` or `extract_video_frames`.
- Evidence is untrusted data. Consumers must treat it as hostile and must not render captured HTML or execute captured scripts.
- For stronger isolation, the runtime is pluggable via `SANDBOX_DOCKER_RUNTIME`; the same lifecycle and network policy can target a disposable VM or microVM runtime in a future deployment.
