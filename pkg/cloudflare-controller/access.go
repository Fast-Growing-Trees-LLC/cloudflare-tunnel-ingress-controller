package cloudflarecontroller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/exposure"
	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/metrics"
	"github.com/cloudflare/cloudflare-go"
	"github.com/go-logr/logr"
	"k8s.io/utils/ptr"
)

// ManagedAccessAppTag marks Access applications created by this controller. It
// is the Access equivalent of the ownership TXT record used for DNS: an Access
// application has no comment field, so ownership rides on tags.
const ManagedAccessAppTag = "ctic-managed"

// ManagedAccessAppTunnelTagFormat scopes ownership to a single tunnel, so that
// two controllers sharing one Cloudflare account never prune each other's
// applications.
//
// The tag body is derived from the tunnel name, not the tunnel id, because
// GetTunnelIdFromTunnelName recreates a tunnel whenever the name is not found.
// An id keyed tag would leave every application carrying a stale tunnel tag
// after any recreation: permanently unowned, never updated, never deleted.
//
// The body is a digest of the name rather than the name itself, see
// accessTagNameMaxLength.
const ManagedAccessAppTunnelTagFormat = "ctic-tunnel-%s"

// accessTagNameMaxLength is Cloudflare's limit on an Access tag name. A longer
// name is rejected by CreateAccessTag with
// "access.api.error.invalid_request: name must be a maximum of 35 characters in
// length (12130)", and ensureOwnershipTags runs before the first application
// create, so one over long tag stalls Access and DNS reconciliation for every
// ingress in the cluster on every pass.
//
// The tunnel name is operator input of unbounded length, so no amount of
// truncating it is a bound the operator cannot beat. The tag carries a fixed
// width digest instead: 12 characters of prefix plus accessTunnelTagHashLength
// is 28, inside the limit for any tunnel name whatsoever.
const accessTagNameMaxLength = 35

// accessTunnelTagHashLength is how much of the tunnel name sha256 the tunnel
// tag carries. 16 hex characters is 64 bits, which makes an accidental
// collision between two tunnel names in one account implausible.
const accessTunnelTagHashLength = 16

// accessPolicyIDPattern is the UUID shape of a reusable Access policy ID.
//
// Only the chart level default policy IDs are checked against the account at
// startup; an id supplied by the access-policies annotation is written by
// anybody who can edit an ingress and is never listed. Letting a malformed one
// reach CreateAccessApplication would abort PutExposures before the DNS step
// and stall DNS reconciliation for every ingress in the cluster, on every
// reconcile. A locally detectable misconfiguration must not do that, so the
// shape is checked here and the hostname is quarantined instead: fail closed
// with a blast radius of one hostname.
var accessPolicyIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AccessApplicationSpec is the fully resolved desired state of one Access
// application.
type AccessApplicationSpec struct {
	Hostname        string
	Name            string // equals Hostname; a field so tests read clearly
	SessionDuration string
	Policies        []string // order is precedence
	AllowedIdps     []string
	Tags            []string // ownership tags, unioned with any tags already on the application
}

type AccessOperationCreate struct{ Spec AccessApplicationSpec }

type AccessOperationUpdate struct {
	OldApplication cloudflare.AccessApplication
	Spec           AccessApplicationSpec
}

type AccessDeleteReason string

const (
	// AccessDeleteReasonWithdrawn means the hostname is no longer exposed. A
	// withdrawn deletion is gated on a positive DNS removal signal.
	AccessDeleteReasonWithdrawn AccessDeleteReason = "withdrawn"
	// AccessDeleteReasonOptedOut means the hostname is still exposed but the
	// access annotation was removed or set to "false". Removing the application
	// makes the hostname public again, so it is logged at warning level.
	AccessDeleteReasonOptedOut AccessDeleteReason = "opted-out"
)

type AccessOperationDelete struct {
	OldApplication cloudflare.AccessApplication
	Reason         AccessDeleteReason
}

// syncAccessApplications computes the Access application operations required to
// reconcile the desired exposures against the applications that currently exist.
// It performs no I/O.
//
// quarantined maps a hostname to a human readable reason why the controller
// cannot safely produce an Access application for it. The caller must withhold
// those hostnames from the tunnel ingress rules and from DNS, so that a
// misconfigured hostname goes dark rather than being published unprotected.
func syncAccessApplications(
	logger logr.Logger,
	exposures []exposure.Exposure,
	existedApplications []cloudflare.AccessApplication,
	tunnelName string,
	tunnelId string,
	defaults exposure.AccessDefaults,
) (
	creates []AccessOperationCreate,
	updates []AccessOperationUpdate,
	deletes []AccessOperationDelete,
	quarantined map[string]string,
	managed int,
	err error,
) {
	effectiveExposures := exposure.Active(exposures)

	desired := make(map[string]AccessApplicationSpec)
	exposedHostnames := make(map[string]struct{})
	quarantined = make(map[string]string)

	// one ingress with N paths yields N exposures with identical annotations,
	// de-duplicate by hostname or every reconcile would attempt N creates
	// against the same Domain
	for _, item := range effectiveExposures {
		hostname := strings.ToLower(item.Hostname)
		exposedHostnames[hostname] = struct{}{}

		// an exposure that does not want Access never removes the wish of one
		// that does, fail closed
		if !item.AccessEnabled {
			continue
		}
		if _, isQuarantined := quarantined[hostname]; isQuarantined {
			continue
		}

		spec := resolveAccessSettings(item, defaults)
		existing, seen := desired[hostname]
		if !seen {
			desired[hostname] = spec
			continue
		}
		// exposure.Exposure carries no ingress identity, so there is no
		// tie-breaker: any winner would be whatever order the ingress listing
		// happened to return, and the effective authorisation decision would
		// flip between reconciles
		if !reflect.DeepEqual(existing, spec) {
			quarantined[hostname] = "two ingresses expose this hostname with conflicting Cloudflare Access settings; make them agree or expose the hostname from a single ingress"
		}
	}

	// completeness validation lives here rather than in the transform because
	// it needs the controller defaults. An application with zero policies
	// denies everyone, so the hostname goes dark instead
	for _, hostname := range slices.Sorted(maps.Keys(desired)) {
		if _, isQuarantined := quarantined[hostname]; isQuarantined {
			continue
		}
		if len(desired[hostname].Policies) == 0 {
			quarantined[hostname] = "access is enabled but no policies are configured; set the " +
				"cloudflare-tunnel-ingress-controller.strrl.dev/access-policies annotation or access.policies in the chart"
			continue
		}
		// a policy id that is not even a UUID would only be rejected by
		// CreateAccessApplication, and that failure aborts the sync before DNS
		// for the whole cluster
		if malformed := malformedPolicyIDs(desired[hostname].Policies); len(malformed) > 0 {
			quarantined[hostname] = "these Cloudflare Access policy IDs are not policy UUIDs: " +
				strings.Join(malformed, ", ") +
				"; the cloudflare-tunnel-ingress-controller.strrl.dev/access-policies annotation takes reusable policy IDs, not policy names"
		}
	}

	for hostname, reason := range quarantined {
		logger.Info("WARNING: hostname withheld from the tunnel and from DNS, its Cloudflare Access configuration is unusable",
			"hostname", hostname, "reason", reason,
		)
	}

	ownership := ownershipTags(tunnelName)

	// forward pass, sorted so the plan is deterministic
	for _, hostname := range slices.Sorted(maps.Keys(desired)) {
		if _, isQuarantined := quarantined[hostname]; isQuarantined {
			continue
		}
		spec := desired[hostname]

		found, existing := findAccessApplicationByDomain(existedApplications, hostname)
		if !found {
			spec.Tags = ownership
			creates = append(creates, AccessOperationCreate{Spec: spec})
			continue
		}

		// deliberate divergence from syncDNSRecord, which adopts an unmanaged
		// CNAME: silently rewriting the policy set of a hand made Access
		// application changes who can reach a production hostname
		if !hasOwnershipTags(existing, tunnelName, tunnelId) {
			logger.Info("access application for hostname already exists and is not managed by this controller, leaving it untouched",
				"hostname", hostname, "application-id", existing.ID,
			)
			metrics.AccessApplicationOperations.WithLabelValues("skipped_unmanaged").Inc()
			continue
		}

		managed++
		// the update replaces the tag list, so the operator's own tags have to
		// be sent back or the first drift driven update silently drops them
		spec.Tags = mergeTags(existing.Tags, ownership)

		if spec.SessionDuration == "" && existing.SessionDuration != "" {
			logger.Info("Cloudflare cannot clear an Access session duration through the API, leaving the existing value in place",
				"hostname", hostname, "session-duration", existing.SessionDuration,
			)
		}
		if len(spec.AllowedIdps) == 0 && len(existing.AllowedIdps) > 0 {
			logger.Info("Cloudflare cannot clear Access identity providers through the API, leaving the existing value in place",
				"hostname", hostname, "allowed-idps", existing.AllowedIdps,
			)
		}

		if accessAppNeedsUpdate(existing, spec) {
			updates = append(updates, AccessOperationUpdate{OldApplication: existing, Spec: spec})
		}
	}

	// reverse pass, driven by owned-but-not-desired rather than by deleted
	// exposures, so an application orphaned by a force deleted ingress is
	// reaped too
	for _, app := range existedApplications {
		if !hasOwnershipTags(app, tunnelName, tunnelId) {
			continue
		}
		hostname := strings.ToLower(app.Domain)
		if _, isDesired := desired[hostname]; isDesired {
			continue
		}
		// a quarantined hostname is not being published, so its application
		// must survive
		if _, isQuarantined := quarantined[hostname]; isQuarantined {
			continue
		}

		reason := AccessDeleteReasonWithdrawn
		if _, stillExposed := exposedHostnames[hostname]; stillExposed {
			reason = AccessDeleteReasonOptedOut
		}
		deletes = append(deletes, AccessOperationDelete{OldApplication: app, Reason: reason})
	}

	return creates, updates, deletes, quarantined, managed, nil
}

// malformedPolicyIDs returns the policy IDs that are not shaped like a
// Cloudflare reusable policy UUID, in the order they were configured.
func malformedPolicyIDs(policies []string) []string {
	var malformed []string
	for _, id := range policies {
		if !accessPolicyIDPattern.MatchString(id) {
			malformed = append(malformed, id)
		}
	}
	return malformed
}

// sawOwnedApplications reports whether this controller owns an Access
// application once this pass has been applied.
//
// The creates count, and it is the whole point: this answer is read by the
// NEXT reconcile to decide whether the account still has to be listed, and an
// application created in this pass is owned from now on. Answering from the
// pre-write listing alone leaves it false for the pass that creates the very
// first application, so a following reconcile with nothing annotated skips the
// listing, plans no deletes, and the documented opt-out silently stops reaping
// until the pod restarts.
func sawOwnedApplications(existedApplications []cloudflare.AccessApplication, creates []AccessOperationCreate, tunnelName string, tunnelId string) bool {
	if len(creates) > 0 {
		return true
	}
	for _, app := range existedApplications {
		if hasOwnershipTags(app, tunnelName, tunnelId) {
			return true
		}
	}
	return false
}

// resolveAccessSettings applies the precedence rule, annotation value beats
// controller default beats Cloudflare's own default. Slice valued annotations
// replace the default, they are never merged: merging list valued security
// configuration is the kind of surprise that produces a fail-open incident.
func resolveAccessSettings(e exposure.Exposure, d exposure.AccessDefaults) AccessApplicationSpec {
	hostname := strings.ToLower(e.Hostname)
	spec := AccessApplicationSpec{
		Hostname: hostname,
		Name:     hostname,
	}

	spec.Policies = d.Policies
	if e.AccessPolicies != nil {
		spec.Policies = e.AccessPolicies
	}

	spec.AllowedIdps = d.AllowedIdps
	if e.AccessAllowedIdps != nil {
		spec.AllowedIdps = e.AccessAllowedIdps
	}

	spec.SessionDuration = d.SessionDuration
	if e.AccessSessionDuration != nil {
		spec.SessionDuration = *e.AccessSessionDuration
	}

	return spec
}

// tunnelTagBody renders a tunnel name as the body of the tunnel ownership tag:
// a fixed width hex prefix of its sha256.
//
// It is a pure function of the name, so it is stable across restarts, across
// replicas and across controller versions; it is case sensitive, so a case only
// rename is still a rename; and it is constant length, so the tag it feeds fits
// accessTagNameMaxLength no matter what the tunnel is called. The name itself is
// deliberately absent from the tag: the tag is an ownership token, not a label a
// human reads, and embedding the name is what made the tag length unbounded.
func tunnelTagBody(tunnelName string) string {
	sum := sha256.Sum256([]byte(tunnelName))
	return hex.EncodeToString(sum[:])[:accessTunnelTagHashLength]
}

// tunnelOwnershipTag is the single generator for the tunnel scoped tag. Every
// site that writes one and every site that compares one goes through here, so
// the plan, the tag creation and hasOwnershipTags cannot drift apart.
func tunnelOwnershipTag(tunnelName string) string {
	return fmt.Sprintf(ManagedAccessAppTunnelTagFormat, tunnelTagBody(tunnelName))
}

// ownershipTags returns the two tags every application this controller creates
// carries, encoding the same two facts the DNS ownership TXT record encodes.
func ownershipTags(tunnelName string) []string {
	return []string{
		ManagedAccessAppTag,
		tunnelOwnershipTag(tunnelName),
	}
}

// hasOwnershipTags reports whether the application was created by this
// controller for this tunnel. The tunnel id form of the tag is accepted as
// well, so a rename or a mid-flight migration produces a one time update that
// rewrites the name form tag rather than a permanent orphan.
func hasOwnershipTags(app cloudflare.AccessApplication, tunnelName string, tunnelId string) bool {
	if !slices.Contains(app.Tags, ManagedAccessAppTag) {
		return false
	}
	if slices.Contains(app.Tags, tunnelOwnershipTag(tunnelName)) {
		return true
	}
	return tunnelId != "" && slices.Contains(app.Tags, fmt.Sprintf(ManagedAccessAppTunnelTagFormat, tunnelId))
}

// policyIDs maps the read type to the write type. AccessPolicy carries a
// Precedence field precisely because slice order is not guaranteed to be
// precedence order, so sort by it first: without the sort an order sensitive
// comparison would report drift on every reconcile and produce a write storm
// against a security object.
func policyIDs(policies []cloudflare.AccessPolicy) []string {
	if len(policies) == 0 {
		return nil
	}
	sorted := slices.Clone(policies)
	slices.SortStableFunc(sorted, func(a, b cloudflare.AccessPolicy) int {
		if v := a.Precedence - b.Precedence; v != 0 {
			return v
		}
		return strings.Compare(a.ID, b.ID)
	})

	ids := make([]string, 0, len(sorted))
	for _, policy := range sorted {
		ids = append(ids, policy.ID)
	}
	return ids
}

// mergeTags unions the tags already on the application with the ownership tags,
// preserving the existing order so an update does not churn.
func mergeTags(actual []string, ownership []string) []string {
	var merged []string
	for _, tag := range append(slices.Clone(actual), ownership...) {
		if !slices.Contains(merged, tag) {
			merged = append(merged, tag)
		}
	}
	return merged
}

// accessAppNeedsUpdate is the read-compare-write guard. PutExposures runs on
// every ingress event cluster wide and on the resync timer, so a non idempotent
// diff would fill the Cloudflare audit log with noise on a security object.
func accessAppNeedsUpdate(actual cloudflare.AccessApplication, desired AccessApplicationSpec) bool {
	if actual.Name != desired.Name {
		return true
	}
	if strings.ToLower(actual.Domain) != desired.Hostname {
		return true
	}
	if actual.Type != cloudflare.SelfHosted {
		return true
	}
	// an empty desired value cannot clear a set one, the params field is
	// omitempty, so an empty desired value is "leave it alone"
	if desired.SessionDuration != "" && actual.SessionDuration != desired.SessionDuration {
		return true
	}
	// allowed_idps is a set, not an ordered list, and shares the same clearing
	// limitation as session_duration
	if len(desired.AllowedIdps) > 0 && !equalStringSets(actual.AllowedIdps, desired.AllowedIdps) {
		return true
	}
	if !slices.Equal(policyIDs(actual.Policies), desired.Policies) {
		return true
	}
	return !equalStringSets(actual.Tags, desired.Tags)
}

func equalStringSets(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := slices.Sorted(slices.Values(a))
	sortedB := slices.Sorted(slices.Values(b))
	return slices.Equal(sortedA, sortedB)
}

// accessCreateParams renders the create request for one planned application.
func accessCreateParams(spec AccessApplicationSpec) cloudflare.CreateAccessApplicationParams {
	return cloudflare.CreateAccessApplicationParams{
		Name:            spec.Name,
		Domain:          spec.Hostname,
		Type:            cloudflare.SelfHosted,
		SessionDuration: spec.SessionDuration,
		AllowedIdps:     spec.AllowedIdps,
		Policies:        spec.Policies,
		Tags:            spec.Tags,
	}
}

// accessUpdateParams renders the update request for one planned application.
//
// Policies must be a non nil pointer. UpdateAccessApplicationParams.Policies is
// a *[]string documented as "if this field is not provided, the existing
// policies will not be modified", so building these params by copying the
// create struct leaves it nil and silently fails to reconcile policy drift.
func accessUpdateParams(operation AccessOperationUpdate) cloudflare.UpdateAccessApplicationParams {
	return cloudflare.UpdateAccessApplicationParams{
		ID:              operation.OldApplication.ID,
		Name:            operation.Spec.Name,
		Domain:          operation.Spec.Hostname,
		Type:            cloudflare.SelfHosted,
		SessionDuration: operation.Spec.SessionDuration,
		AllowedIdps:     operation.Spec.AllowedIdps,
		Policies:        ptr.To(operation.Spec.Policies),
		Tags:            operation.Spec.Tags,
	}
}

// findAccessApplicationByDomain joins on the lowercased Domain, Cloudflare
// lowercases it and Kubernetes does not.
func findAccessApplicationByDomain(apps []cloudflare.AccessApplication, hostname string) (bool, cloudflare.AccessApplication) {
	for _, app := range apps {
		if strings.ToLower(app.Domain) == hostname {
			return true, app
		}
	}
	return false, cloudflare.AccessApplication{}
}
