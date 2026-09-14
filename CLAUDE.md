# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Kubernetes Ingress Controller that integrates with Cloudflare Tunnel to expose Kubernetes services to the internet securely without requiring port forwarding or firewall configuration. It watches Kubernetes Ingress resources and automatically configures Cloudflare Tunnels to route traffic to the corresponding services.

For the data flow, DNS ownership model, and connector reconciliation design, see the [architecture explanation](https://tunnel.strrl.dev/explanation/architecture/).

## Architecture Orientation

- **IngressController** (`pkg/controller/ingress-controller.go`): Reconciles controlled Kubernetes Ingress resources
- **Ingress transformation** (`pkg/controller/transform.go`): Converts Ingress rules and Services into Exposure objects
- **Exposure** (`pkg/exposure/exposure.go`): Internal representation shared between Kubernetes and Cloudflare logic
- **TunnelClient** (`pkg/cloudflare-controller/tunnel-client.go`): Reconciles tunnel ingress rules and DNS records through the Cloudflare API
- **DNS ownership** (`pkg/cloudflare-controller/dns.go`): Plans CNAME and ownership TXT record changes
- **ControlledCloudflaredConnector** (`pkg/controller/controlled-cloudflared-connector.go`): Reconciles the managed cloudflared Secret and Deployment, owned by the controller Deployment so garbage collection removes them on uninstall; the Cloudflare tunnel itself is intentionally kept and reused by name

## Development Commands

```bash
# Initial setup (installs pre-commit hooks via prek)
make setup

# Run unit tests
make unit-test

# Run a single test
go test -run TestFunctionName ./pkg/path/to/package/...

# Run integration tests (requires setup-envtest)
make integration-test

# Build Docker image
make image

# Development with live reload (also runs setup)
make dev
```

### Pre-commit Hooks

Pre-commit hooks are managed via [prek](https://prek.j178.dev/) (configured in `prek.toml`). Hooks run `gofmt`, `go vet`, and `golangci-lint` automatically before each commit. Run `make setup` after cloning to install them.

## Configuration

### Required Flags
- `--cloudflare-api-token`: Cloudflare API token with Zone:Zone:Read, Zone:DNS:Edit and Account:Cloudflare Tunnel:Edit permissions
- `--cloudflare-account-id`: Cloudflare account ID
- `--cloudflare-tunnel-name`: Name of the Cloudflare tunnel to manage
- `--ingress-class`: Ingress class name (default: "cloudflare-tunnel")
- `--controller-class`: Controller class name (default: "strrl.dev/cloudflare-tunnel-ingress-controller")
- `--namespace`: Namespace to execute cloudflared connector (default: "default")
- `--access-enabled`: Manage Cloudflare Access applications for annotated ingresses (default: false). While false the controller makes no Access API calls; enabling it also requires `Access: Apps Write` on the API token
- `--access-policies`: Default reusable Access policy IDs, ascending precedence (repeatable, default: empty)
- `--access-allowed-idps`: Default Access identity provider IDs (repeatable, default: empty)
- `--access-session-duration`: Default Access session duration as a non negative Go duration string, e.g. "24h" or "1h30m" (default: empty, Cloudflare's own default)
- `--access-resync-interval`: How often each controlled ingress is re-reconciled so out-of-band Access drift is repaired (default: 10m, 0 disables)

### Supported Annotations
- `cloudflare-tunnel-ingress-controller.strrl.dev/proxy-ssl-verify`: Enable/disable SSL verification ("on" or "off", default: "off")
- `cloudflare-tunnel-ingress-controller.strrl.dev/backend-protocol`: Backend protocol (default: "http")
- `cloudflare-tunnel-ingress-controller.strrl.dev/http-host-header`: Set HTTP Host header for the local webserver
- `cloudflare-tunnel-ingress-controller.strrl.dev/origin-server-name`: Hostname on the origin server certificate
- `cloudflare-tunnel-ingress-controller.strrl.dev/disable-dns-management`: Disable Cloudflare DNS record (CNAME/TXT) management for the ingress while still configuring the tunnel ingress rule, so DNS can be delegated to an external system such as external-dns or a Cloudflare Load Balancer ("true" or "false", default "false")
- `cloudflare-tunnel-ingress-controller.strrl.dev/access`: Manage a Cloudflare Access application in front of every hostname produced by the ingress ("true" or "false", default "false"). Requires `--access-enabled`; cannot be combined with `disable-dns-management` or used on a wildcard host
- `cloudflare-tunnel-ingress-controller.strrl.dev/access-policies`: Comma separated existing reusable Access policy IDs, ascending precedence (default: `--access-policies`)
- `cloudflare-tunnel-ingress-controller.strrl.dev/access-allowed-idps`: Comma separated Access identity provider IDs (default: `--access-allowed-idps`)
- `cloudflare-tunnel-ingress-controller.strrl.dev/access-session-duration`: Access session duration as a non negative Go duration string such as "24h" or "1h30m", or "0s" to re-authenticate every request (default: `--access-session-duration`)
- Origin request settings mapping to cloudflared `originRequest` fields (see `pkg/controller/well_known_annotations.go`): `connect-timeout`, `tls-timeout`, `tcp-keepalive`, `no-happy-eyeballs`, `keepalive-connections`, `keepalive-timeout`, `no-tls-verify`, `disable-chunked-encoding`, `http2-origin`

## Testing Strategy

### Unit Tests
Located in `pkg/` directories alongside source files (e.g., `dns_test.go`, `transform_test.go`).

### Integration Tests
Located in `test/integration/` using Ginkgo/Gomega framework with envtest for Kubernetes API simulation. The `hack/install-setup-envtest.sh` script installs `setup-envtest` if not present.

## Deployment

Helm chart in `helm/cloudflare-tunnel-ingress-controller/`. Example dev configurations in `hack/dev/`.
