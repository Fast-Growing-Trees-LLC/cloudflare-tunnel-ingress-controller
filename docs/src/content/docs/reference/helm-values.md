---
title: Helm Values
description: Tune the controller and cloudflared connectors with chart values.
---

The `strrl.dev/cloudflare-tunnel-ingress-controller` chart exposes values for production hardening, observability, and connector behaviour. The tables below cover common settings and pod customization.

For the complete and up-to-date list of all available Helm values, refer to the [values.yaml](https://github.com/STRRL/cloudflare-tunnel-ingress-controller/blob/master/helm/cloudflare-tunnel-ingress-controller/values.yaml) file in the repository.

## Credentials and ingress

| Value                         | Default             | Notes                                                                                      |
| ----------------------------- | ------------------- | ------------------------------------------------------------------------------------------ |
| `cloudflare.apiToken`         | `""`                | Required when Helm creates the credential Secret.                                          |
| `cloudflare.accountId`        | `""`                | Required when Helm creates the credential Secret.                                          |
| `cloudflare.tunnelName`       | `""`                | Required when Helm creates the credential Secret.                                          |
| `cloudflare.secretRef.*`      | unset               | Use an existing Secret. Set `name`, `accountIDKey`, `tunnelNameKey`, and `apiTokenKey`.    |
| `ingressClass.name`           | `cloudflare-tunnel` | Name of the `IngressClass` created and watched by the controller.                          |
| `ingressClass.isDefaultClass` | `false`             | Set to `true` only if Cloudflare Tunnel should handle ingresses without an explicit class. |

## Cloudflare Access

These values control the optional Cloudflare Access integration described in [Protect a hostname with Cloudflare Access](/how-to/protect-with-cloudflare-access/). Enabling it requires the API token to additionally carry the `Account:Access: Apps and Policies:Edit` permission. While `access.enabled` is `false` the whole block is inert: the controller makes no Access API calls, and an ingress that asks for Access is not exposed. Setting `access.resyncInterval` to `0` means an Access application deleted outside Kubernetes leaves its hostname public until something in the cluster changes.

Configure a policy before any ingress asks for Access. An application with no policy denies everyone, so rather than create one the controller withholds the hostname: it removes the tunnel rule and deletes the controller-owned DNS records, which takes a hostname that is currently serving traffic offline. There is no Ingress event for it, only a controller log warning and a non-zero `cloudflare_tunnel_ingress_controller_access_quarantined_hostnames`. Leaving `access.policies` empty is safe only while every Access-annotated ingress sets `access-policies` itself.

| Value                    | Default | Notes                                                                                                                                                                                                                                                                                             |
| ------------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `access.enabled`         | `false` | Manage Access applications for ingresses carrying the `access` annotation.                                                                                                                                                                                                                        |
| `access.policies`        | `[]`    | Reusable Access policy IDs (UUIDs, not policy names) attached to every managed application, in ascending order of precedence. Create them in the Zero Trust dashboard first: the controller attaches policies, it never creates or edits them. Validated once at startup, an unknown ID stops the controller from starting. An Access-annotated hostname left with no policy is taken offline rather than published unprotected. |
| `access.allowedIdps`     | `[]`    | Access identity provider IDs. Empty lets Cloudflare apply the organisation default. Emptying this value later does not clear the identity providers on applications that already have them, the Cloudflare API has no way to express that.                                                        |
| `access.sessionDuration` | `""`    | Access session duration as a non-negative Go duration string, such as `24h`, `1h30m`, or `0s` to re-authenticate on every request. Empty lets Cloudflare apply its own default. As with `allowedIdps`, emptying it later does not reset the duration on applications that already have one. |
| `access.resyncInterval`  | `10m`   | How often each controlled Ingress is reconciled again so an application deleted outside Kubernetes is recreated. `0` disables the resync.                                                                                                                                                         |

Each value is a default that an ingress can override with the matching `access-*` annotation. See [Ingress annotations](/reference/ingress-annotations/).

## Controller pods

These values apply to the controller Deployment, not the managed cloudflared connector Deployment.

| Value                | Default                                                              | Notes                                                                                        |
| -------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `replicaCount`       | `1`                                                                  | Number of controller pods. Enable `leaderElection.enabled` when using more than one replica. |
| `resources`          | CPU requests and limits: `100m`; memory requests and limits: `128Mi` | Controller container resource requests and limits.                                           |
| `securityContext`    | `{}`                                                                 | Kubernetes container security context for the controller container.                          |
| `podSecurityContext` | `{}`                                                                 | Kubernetes pod security context for controller pods.                                         |
| `priorityClassName`  | unset                                                                | PriorityClass assigned to controller pods.                                                   |

## Managed cloudflared connector pods

The chart writes these values to the deployment customization file consumed by the controller.

| Value                                   | Default  | Notes                                                                                                                                                                               |
| --------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cloudflared.image.tag`                 | `latest` | Image tag for managed cloudflared connector pods.                                                                                                                                   |
| `cloudflared.replicaCount`              | `1`      | Number of cloudflared connector pods maintaining the tunnel.                                                                                                                        |
| `cloudflared.extraArgs`                 | `[]`     | Extra arguments passed to cloudflared, such as `--post-quantum`.                                                                                                                    |
| `cloudflared.resources`                 | `{}`     | Container resource requests and limits.                                                                                                                                             |
| `cloudflared.securityContext`           | `{}`     | Kubernetes container security context for the cloudflared container.                                                                                                                |
| `cloudflared.podSecurityContext`        | `{}`     | Kubernetes pod security context for connector pods.                                                                                                                                 |
| `cloudflared.podAntiAffinity`           | `false`  | Adds required pod anti-affinity across `kubernetes.io/hostname`. Ignored when `cloudflared.affinity` is set. Extra replicas stay pending if there are not enough schedulable nodes. |
| `cloudflared.topologySpreadConstraints` | `[]`     | Kubernetes topology spread constraints for connector pods.                                                                                                                          |
| `cloudflared.priorityClassName`         | unset    | PriorityClass assigned to connector pods.                                                                                                                                           |
| `cloudflared.probes.liveness`           | `{}`     | Kubernetes liveness probe for the cloudflared container.                                                                                                                            |
| `cloudflared.probes.readiness`          | `{}`     | Kubernetes readiness probe for the cloudflared container.                                                                                                                           |
| `cloudflared.probes.startup`            | `{}`     | Kubernetes startup probe for the cloudflared container.                                                                                                                             |
| `cloudflared.volumes`                   | `[]`     | Kubernetes volumes added to connector pods.                                                                                                                                         |
| `cloudflared.volumeMounts`              | `[]`     | Kubernetes volume mounts added to the cloudflared container.                                                                                                                        |
| `cloudflared.pdb.enabled`               | `false`  | Create a PodDisruptionBudget for connector pods.                                                                                                                                    |
| `cloudflared.pdb.minAvailable`          | unset    | Minimum available connector pods. Mutually exclusive with `cloudflared.pdb.maxUnavailable`.                                                                                         |
| `cloudflared.pdb.maxUnavailable`        | unset    | Maximum unavailable connector pods. Mutually exclusive with `cloudflared.pdb.minAvailable`.                                                                                         |

## Cloudflared ServiceMonitor

These values configure the Prometheus Operator `ServiceMonitor` for managed cloudflared connectors.

| Value                                         | Default | Notes                                                                                      |
| --------------------------------------------- | ------- | ------------------------------------------------------------------------------------------ |
| `cloudflaredServiceMonitor.create`            | `false` | Create the ServiceMonitor.                                                                 |
| `cloudflaredServiceMonitor.jobLabel`          | `""`    | Service label used as the Prometheus job name. Omitted from the ServiceMonitor when empty. |
| `cloudflaredServiceMonitor.interval`          | `""`    | Scrape interval. Omitted from the endpoint when empty.                                     |
| `cloudflaredServiceMonitor.scrapeTimeout`     | `""`    | Scrape timeout. Omitted from the endpoint when empty.                                      |
| `cloudflaredServiceMonitor.honorLabels`       | `false` | Preserve labels from scraped metrics when they conflict with server-side labels.           |
| `cloudflaredServiceMonitor.metricRelabelings` | `[]`    | Metric relabeling rules applied after scraping.                                            |
| `cloudflaredServiceMonitor.relabelings`       | `[]`    | Target relabeling rules applied before scraping.                                           |
| `cloudflaredServiceMonitor.labels`            | `{}`    | Additional labels added to the ServiceMonitor.                                             |
| `cloudflaredServiceMonitor.scheme`            | `http`  | Scheme used to scrape the metrics endpoint.                                                |

## Uninstall behaviour

The connector Deployment and the tunnel token Secret are created by the controller at runtime with an owner reference to the controller Deployment. Kubernetes garbage collection removes them when the release is uninstalled, so no cloudflared pods keep running against a stale tunnel.

External resources are never touched during uninstall, following the same model as other ingress controllers:

- The Cloudflare tunnel is kept. Tunnels are addressed by name, a reinstall with the same `cloudflare.tunnelName` reuses it. Delete it from the Cloudflare dashboard (or via API) when it is no longer needed.
- DNS records are cleaned up by the controller whenever an Ingress is deleted. Delete your Ingress resources before uninstalling if you want the records removed; records belonging to Ingresses that still exist at uninstall time stay behind together with the tunnel.
