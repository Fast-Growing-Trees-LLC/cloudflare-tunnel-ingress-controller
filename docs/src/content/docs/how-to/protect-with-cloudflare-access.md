---
title: Protect a Hostname with Cloudflare Access
description: Put a Zero Trust identity check in front of a hostname the controller already exposes.
---

You exposed a hostname and it is now public. Cloudflare Access puts an identity check in front of it without changing your Service or adding a sidecar.

This guide enables the integration on the controller, points it at a policy you already have, and turns Access on for one ingress. It assumes you finished the [quickstart](/guides/quickstart/) and it does not teach Zero Trust: see the Cloudflare [Access applications](https://developers.cloudflare.com/cloudflare-one/applications/) documentation for the product itself.

## Before you start

- A Cloudflare Zero Trust account on the same account ID the controller already uses.
- At least one reusable Access policy. The controller attaches policies, it never creates or edits them.
- Permission to edit the API token the controller uses.

## 1. Add the Access permission to the API token

The controller needs a fourth permission scope, `Account:Access: Apps and Policies:Edit`, alongside the three from the quickstart. Edit the existing token in the Cloudflare dashboard under **My Profile**, **API Tokens**, or create a replacement with all four scopes as described in [Cloudflare credentials](/reference/cloudflare-credentials/).

The controller reads its credentials once at startup, so a running controller keeps using the permissions it started with. Restart it after editing the token, or follow [Rotate Cloudflare credentials](/how-to/rotate-cloudflare-credentials/) when you replace the token instead of editing it.

## 2. Find your policy ID

Open **Zero Trust**, **Access**, **Policies** in the Cloudflare dashboard and copy the ID of the policy you want to apply. The same list is available from the API:

```bash
curl -s -H "Authorization: Bearer <CLOUDFLARE_API_TOKEN>" \
  "https://api.cloudflare.com/client/v4/accounts/<CLOUDFLARE_ACCOUNT_ID>/access/policies"
```

Reusable policies are the intended input. Policies created inline on a single application are not addressable by ID and cannot be used here, and the controller never creates, edits, or deletes a policy: their lifecycle stays in the dashboard or in your own Terraform.

The controller checks these IDs once at startup and refuses to start if one of them is not a reusable policy on the account. A typo therefore shows up as a crash-looping pod with the offending ID in its log, not as a hostname that silently lost its protection.

## 3. Enable Access on the controller

Turn the integration on and set the account-wide defaults. Individual ingresses stay short because they inherit these values:

```bash
helm upgrade --install --wait \
  cloudflare-tunnel-ingress-controller \
  cloudflare-tunnel-ingress-controller \
  --repo https://helm.strrl.dev \
  --namespace cloudflare-tunnel-ingress-controller \
  --reuse-values \
  --set access.enabled=true \
  --set access.policies[0]="<ACCESS_POLICY_ID>" \
  --set access.sessionDuration="24h"
```

With `access.enabled` false, the chart default, the controller makes no Access API calls at all and an ingress that asks for Access is not exposed. See [Helm values](/reference/helm-values/) for every value in the block.

The controller also re-checks its applications every `access.resyncInterval`, ten minutes by default, so an application deleted in the Cloudflare dashboard is recreated without waiting for something to change in Kubernetes.

## 4. Turn on Access for one ingress

Add the `access` annotation to an Ingress that already works:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: dashboard
  namespace: kubernetes-dashboard
  annotations:
    cloudflare-tunnel-ingress-controller.strrl.dev/access: "true"
spec:
  ingressClassName: cloudflare-tunnel
  rules:
    - host: dash.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: kubernetes-dashboard
                port:
                  number: 80
```

```bash
kubectl apply -f dashboard-ingress.yaml
```

Override the controller defaults per ingress when one hostname needs different policies or a shorter session:

```yaml
metadata:
  annotations:
    cloudflare-tunnel-ingress-controller.strrl.dev/access: "true"
    cloudflare-tunnel-ingress-controller.strrl.dev/access-policies: "<ACCESS_POLICY_ID>,<SECOND_ACCESS_POLICY_ID>"
    cloudflare-tunnel-ingress-controller.strrl.dev/access-session-duration: "1h"
```

An annotation replaces the controller default rather than merging with it, and policies apply in ascending order of precedence. See [Ingress annotations](/reference/ingress-annotations/) for every key.

Two things can go wrong on a hostname that is already serving traffic, so verify rather than assume. If no policy resolves for the hostname, from either source, the controller withholds it instead of creating an application that denies everyone: the tunnel rule and the DNS records go away, and the hostname goes down with no Ingress event to say so. If instead the Access step itself fails, most often because the token cannot manage Access applications yet, the sync stops before the DNS step and the hostname simply stays public with no application in front of it, for as long as the failure lasts. The resync does not shorten that, because it runs the same sync. Step 5 is what distinguishes the two.

## 5. Verify

Check the Ingress for warning events first. A healthy ingress reports none:

```bash
kubectl describe ingress dashboard -n kubernetes-dashboard
```

Then find the create in the controller log:

```bash
kubectl logs deployment/cloudflare-tunnel-ingress-controller \
  -n cloudflare-tunnel-ingress-controller | grep -i access
```

Finally, request the hostname:

```bash
curl -sI https://dash.example.com/
```

A client without an Access session gets a `302` to `<YOUR_TEAM>.cloudflareaccess.com`, which is the login redirect and the clearest sign the application is in place. A client that already satisfies an allow policy, such as a device enrolled in WARP, gets a `200` instead, and the application is still doing its job. Confirm the unambiguous version in **Zero Trust**, **Access**, **Applications**: the hostname is listed as a self-hosted application carrying the `ctic-managed` tag. A `200` with no application listed there is the failure case from step 4: the hostname is still public, and the Ingress carries a `CloudflareSyncFailed` event naming the reason. See [Troubleshooting](/guides/troubleshooting/).

## What the controller owns

The controller creates one self-hosted application per opted-in hostname, named after the hostname and tagged with `ctic-managed` and a tag derived from the tunnel name. The tunnel name is what lets the controller recognise its own work after a tunnel is deleted and recreated, and it keeps two clusters that share one Cloudflare account from pruning each other's applications.

The controller never modifies or deletes an application it did not create. If an application already exists for the hostname, it is left exactly as it is and the controller logs a warning: the hostname stays protected by your own configuration, but this controller is not enforcing Access on it, so nothing it does to the ingress changes who can reach that hostname.

One application covers the whole hostname. It therefore gates every path on that hostname, including paths served by a different Ingress, a different ingress class, or another ingress controller entirely.

## Limitations

Access cannot be combined with `disable-dns-management: "true"`. Removing an application is only safe once the hostname has stopped resolving, and the controller has no way to confirm that for a DNS record it does not manage.

Access cannot be used on a wildcard host such as `*.example.com`. Cloudflare validates wildcard application domains differently and gates them by plan, so a wildcard application is one you should create deliberately in the dashboard rather than have a controller infer.

Both combinations are rejected at transform time with a `TransformFailed` warning event, and the ingress is not exposed until you fix it.

## Turning Access off

Removing Access from a live hostname makes it public again on the next reconciliation. Remove **all four** `access-*` annotations together. Leaving one behind is a validation error that takes the hostname down instead of making it public, which is the safer failure but rarely the one you wanted.

```bash
kubectl annotate ingress dashboard -n kubernetes-dashboard \
  cloudflare-tunnel-ingress-controller.strrl.dev/access- \
  cloudflare-tunnel-ingress-controller.strrl.dev/access-policies- \
  cloudflare-tunnel-ingress-controller.strrl.dev/access-allowed-idps- \
  cloudflare-tunnel-ingress-controller.strrl.dev/access-session-duration-
```

The controller deletes the Access application and logs the removal at warning level. If you wanted the hostname to stop being reachable rather than to become public, delete the Ingress instead.

Confirm the hostname is serving without the identity check before you walk away:

```bash
kubectl describe ingress dashboard -n kubernetes-dashboard
curl -sI https://dash.example.com/
```

For the annotation syntax see [Ingress annotations](/reference/ingress-annotations/), for the chart block [Helm values](/reference/helm-values/), for the ownership and ordering model [Architecture](/explanation/architecture/), and for failure symptoms [troubleshooting](/guides/troubleshooting/).
