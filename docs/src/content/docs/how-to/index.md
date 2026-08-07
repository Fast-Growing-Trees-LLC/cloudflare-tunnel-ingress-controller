---
title: How To Guides
description: Complete common operational tasks with a running Cloudflare Tunnel Ingress Controller.
---

:::tip[Can't find the how-to you need?]
The how-to quadrant is driven by real user tasks. [Tell us what you are trying to do](https://github.com/STRRL/cloudflare-tunnel-ingress-controller/issues/new?template=docs-request.yml).
:::

Use these guides after the controller and its managed `cloudflared` connectors are running.

1. [Expose non HTTP services](/how-to/expose-non-http-services/): Publish TCP, SSH, RDP, and other supported service protocols.
2. [Protect a hostname with Cloudflare Access](/how-to/protect-with-cloudflare-access/): Put a Zero Trust identity check in front of a hostname you already expose.
3. [Use an external DNS system](/how-to/use-with-external-dns/): Hand DNS ownership to ExternalDNS or a Cloudflare Load Balancer.
4. [Configure high availability](/how-to/high-availability/): Run redundant controller and `cloudflared` replicas across failure domains.
5. [Monitor the controller and cloudflared](/how-to/monitoring/): Scrape metrics and add health probes.
6. [Rotate Cloudflare credentials](/how-to/rotate-cloudflare-credentials/): Replace the API token without leaving workloads on stale credentials.
