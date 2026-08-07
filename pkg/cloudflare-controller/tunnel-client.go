package cloudflarecontroller

import (
	"bytes"
	"context"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/exposure"
	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/metrics"
	"github.com/cloudflare/cloudflare-go"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
)

type TunnelClientInterface interface {
	PutExposures(ctx context.Context, exposures []exposure.Exposure) error
	TunnelDomain() string
	FetchTunnelToken(ctx context.Context) (string, error)
}

var _ TunnelClientInterface = &TunnelClient{}

type TunnelClient struct {
	logger             logr.Logger
	cfClient           *cloudflare.API
	accountId          string
	tunnelId           string
	tunnelName         string
	dnsCommentTemplate *template.Template // nil if disabled (empty template string)
	// access is the single source of truth for whether Access is enabled, the
	// ingress controller holds the same value
	access exposure.AccessDefaults

	accessMutex sync.Mutex
	// accessListedOnce records that this process has listed the account's
	// Access applications at least once, so a later reconcile may skip the call
	accessListedOnce bool
	// sawOwnedApplications keeps the reverse pass alive while this controller
	// still owns an application, even when no exposure asks for Access
	sawOwnedApplications bool
	// ownershipTagsEnsured latches on success, not on call: a transient failure
	// must not disable tag creation for the rest of the process lifetime, an
	// untagged application is permanently unmanageable
	ownershipTagsEnsured bool
}

// accessPlan is the result of one read only Access planning pass.
type accessPlan struct {
	creates     []AccessOperationCreate
	updates     []AccessOperationUpdate
	deletes     []AccessOperationDelete
	quarantined map[string]string
	managed     int
}

// DNSCommentTemplateData contains the variables available in the DNS comment template.
// See https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/
// for comment length limits per Cloudflare plan (Free: 100, Pro/Business/Enterprise: 500 chars).
type DNSCommentTemplateData struct {
	TunnelName string // Name of the Cloudflare Tunnel
	TunnelId   string // ID of the Cloudflare Tunnel
	Hostname   string // DNS record hostname (e.g. "app.example.com")
}

func NewTunnelClient(logger logr.Logger, cfClient *cloudflare.API, accountId string, tunnelId string, tunnelName string, dnsCommentTemplate string, access exposure.AccessDefaults) *TunnelClient {
	tc := &TunnelClient{
		logger:     logger,
		cfClient:   cfClient,
		accountId:  accountId,
		tunnelId:   tunnelId,
		tunnelName: tunnelName,
		access:     access,
	}
	if dnsCommentTemplate != "" {
		tmpl, err := template.New("dns-comment").Parse(dnsCommentTemplate)
		if err != nil {
			logger.Error(err, "failed to parse dns-comment-template, DNS comments will be disabled", "template", dnsCommentTemplate)
		} else {
			tc.dnsCommentTemplate = tmpl
		}
	}
	return tc
}

// renderDNSComment renders the DNS comment for a given hostname using the configured template.
// Returns empty string if the template is disabled or rendering fails.
func (t *TunnelClient) renderDNSComment(hostname string) string {
	if t.dnsCommentTemplate == nil {
		return ""
	}
	data := DNSCommentTemplateData{
		TunnelName: t.tunnelName,
		TunnelId:   t.tunnelId,
		Hostname:   hostname,
	}
	var buf bytes.Buffer
	if err := t.dnsCommentTemplate.Execute(&buf, data); err != nil {
		t.logger.Error(err, "failed to render dns comment template", "hostname", hostname)
		return ""
	}
	comment := buf.String()

	// Warn about comment length.
	// Cloudflare enforces per-plan limits: Free=100, Pro/Business/Enterprise=500 chars.
	// See https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/
	if len(comment) > 100 {
		t.logger.Info("rendered DNS comment exceeds 100 characters (Cloudflare Free plan limit, Pro/Business/Enterprise allow 500)",
			"hostname", hostname, "commentLength", len(comment),
		)
	}
	return comment
}

func (t *TunnelClient) PutExposures(ctx context.Context, exposures []exposure.Exposure) error {
	// Read only. Planning first means a token missing the Access scope aborts
	// the sync before anything is written, so a hostname is never published.
	plan, err := t.planAccessApplications(ctx, exposures)
	if err != nil {
		return errors.Wrap(err, "plan access applications")
	}

	// A hostname the planner could not safely produce an application for is
	// withheld from the tunnel and from DNS, so it goes dark rather than being
	// published without the protection its annotations asked for.
	routable := withoutQuarantined(exposures, plan.quarantined)

	if err := t.updateTunnelIngressRules(ctx, routable); err != nil {
		return errors.Wrap(err, "update tunnel ingress rules")
	}

	// Access applications are created before the DNS record publishes the
	// hostname, so a hostname never resolves without its application in place.
	if err := t.applyAccessUpserts(ctx, plan); err != nil {
		return errors.Wrap(err, "apply access applications")
	}

	// removed is the set of hostnames whose CNAME this pass positively removed
	// or positively observed to be absent. It is NOT "the DNS step succeeded":
	// the relinquish path in syncDNSRecord deliberately keeps a CNAME that has
	// been repointed elsewhere, and returning nil in that case says nothing
	// about whether the hostname still resolves.
	removed, err := t.updateDNSCNAMERecord(ctx, routable, withdrawnHostnames(plan))
	if err != nil {
		return errors.Wrap(err, "update DNS CNAME record")
	}

	// An Access application is removed only once the tunnel ingress rule is gone
	// AND, for a withdrawn hostname, the DNS record is confirmed gone.
	if err := t.applyAccessDeletes(ctx, plan, removed); err != nil {
		return errors.Wrap(err, "delete access applications")
	}

	metrics.ManagedExposures.Set(float64(len(exposure.Active(routable))))
	metrics.QuarantinedHostnames.Set(float64(len(plan.quarantined)))
	if t.access.Enabled {
		metrics.ManagedAccessApplications.Set(float64(plan.managed))
	}
	metrics.LastSuccessfulSyncTimestamp.Set(float64(time.Now().Unix()))
	return nil
}

// withoutQuarantined drops every exposure whose hostname the planner refused to
// produce an Access application for.
func withoutQuarantined(exposures []exposure.Exposure, quarantined map[string]string) []exposure.Exposure {
	if len(quarantined) == 0 {
		return exposures
	}
	var routable []exposure.Exposure
	for _, item := range exposures {
		if _, isQuarantined := quarantined[strings.ToLower(item.Hostname)]; isQuarantined {
			continue
		}
		routable = append(routable, item)
	}
	return routable
}

// withdrawnHostnames are the hostnames whose Access application may only be
// deleted once their DNS record is confirmed gone.
func withdrawnHostnames(plan accessPlan) map[string]struct{} {
	hostnames := make(map[string]struct{})
	for _, item := range plan.deletes {
		if item.Reason == AccessDeleteReasonWithdrawn {
			hostnames[strings.ToLower(item.OldApplication.Domain)] = struct{}{}
		}
	}
	return hostnames
}

// accessPolicyLister lists the account's reusable Access policies. It exists so
// the startup validation's retry and degrade behaviour can be tested without a
// live Cloudflare API.
type accessPolicyLister func(ctx context.Context) ([]cloudflare.AccessPolicy, error)

const (
	// accessPolicyValidationAttempts bounds the startup listing retry. Three
	// tries ride out a transient 5xx without meaningfully delaying pod startup.
	accessPolicyValidationAttempts = 3
	// accessPolicyValidationBackoff is the wait before the second attempt, and
	// is doubled for each attempt after that.
	accessPolicyValidationBackoff = 2 * time.Second
)

// validateAccessPolicies runs once at startup when Access is enabled. It lists
// the account's reusable Access policies and returns an error naming every
// configured default policy ID that does not exist. An invalid policy UUID is
// otherwise not detected until a create fails at runtime, which would stall the
// sync for the whole cluster instead of crash looping one pod with a message
// naming the bad ID.
//
// A listing that fails outright is a different thing from a listing that
// succeeds and comes back without one of the configured IDs, and the two are
// deliberately not treated alike. See validateAccessPoliciesWith.
func (t *TunnelClient) validateAccessPolicies(ctx context.Context) error {
	return t.validateAccessPoliciesWith(ctx, t.listAccessPolicies, accessPolicyValidationAttempts, accessPolicyValidationBackoff)
}

func (t *TunnelClient) listAccessPolicies(ctx context.Context) ([]cloudflare.AccessPolicy, error) {
	policies, _, err := t.cfClient.ListAccessPolicies(ctx, cloudflare.AccountIdentifier(t.accountId), cloudflare.ListAccessPoliciesParams{})
	return policies, err
}

// validateAccessPoliciesWith is validateAccessPolicies with the listing, the
// attempt count and the backoff injected.
//
// The two failure directions are not symmetric:
//
//   - The listing succeeded and a configured ID is not among the results. That
//     is a settled fact about the configuration, so it is fatal: the pod
//     refuses to start with a message naming the bad ID.
//   - The listing itself failed - network, 5xx, a token without the read scope.
//     After a bounded retry this logs loudly, names the policy IDs it could not
//     verify, and starts anyway.
//
// Starting anyway is the point. This validation is an early-warning
// optimisation, not the safety mechanism: a malformed policy ID is quarantined
// at plan time and a well formed but nonexistent one fails fast at create time,
// so no hostname is ever published without the protection its annotations asked
// for whether or not this check ran. Refusing to start because the listing
// errored would trade a small diagnostic head start for a cluster-wide DNS
// outage - every ingress in the cluster stops reconciling because one read call
// returned a 403 or a 502.
func (t *TunnelClient) validateAccessPoliciesWith(ctx context.Context, list accessPolicyLister, attempts int, backoff time.Duration) error {
	if !t.access.Enabled || len(t.access.Policies) == 0 {
		return nil
	}

	policies, err := listWithRetry(ctx, list, attempts, backoff)
	if err != nil {
		t.logger.Error(err, "WARNING: could not list Cloudflare Access policies at startup, starting anyway with the configured policy IDs unverified; a bad ID will now surface as a failed Access application create instead of a startup failure",
			"unverifiedPolicyIDs", strings.Join(t.access.Policies, ", "), "attempts", attempts)
		return nil
	}

	var known []string
	for _, policy := range policies {
		known = append(known, policy.ID)
	}

	var missing []string
	for _, id := range t.access.Policies {
		if !slices.Contains(known, id) {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return errors.Errorf("configured access policies are not reusable policies on this account: %s", strings.Join(missing, ", "))
	}
	return nil
}

// listWithRetry calls list up to attempts times with an exponential backoff,
// counting every failure on cloudflare_api_errors_total. A cancelled context
// stops the retry immediately - there is nothing to wait for once the process
// is shutting down.
func listWithRetry(ctx context.Context, list accessPolicyLister, attempts int, backoff time.Duration) ([]cloudflare.AccessPolicy, error) {
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		var policies []cloudflare.AccessPolicy
		policies, err = list(ctx)
		if err == nil {
			return policies, nil
		}
		metrics.CloudflareAPIErrors.WithLabelValues("list_access_policies").Inc()
		if attempt == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, errors.Wrap(err, "list access policies")
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, errors.Wrapf(err, "list access policies, %d attempt(s)", attempts)
}

// planAccessApplications lists the account's Access applications and computes
// the plan. It is read only. It returns a zero plan and no error when Access is
// not enabled, or when the list can safely be skipped.
func (t *TunnelClient) planAccessApplications(ctx context.Context, exposures []exposure.Exposure) (accessPlan, error) {
	if !t.access.Enabled {
		return accessPlan{}, nil
	}

	wanted := false
	for _, item := range exposure.Active(exposures) {
		if item.AccessEnabled {
			wanted = true
			break
		}
	}

	t.accessMutex.Lock()
	listedOnce := t.accessListedOnce
	sawOwned := t.sawOwnedApplications
	t.accessMutex.Unlock()

	// enabling the chart flag on its own must not add a per reconcile API call:
	// with nothing annotated and nothing owned there is nothing to create and
	// nothing to reap. The first reconcile of the process always lists, so an
	// application whose annotation was removed while the pod was down is still
	// reaped.
	if listedOnce && !wanted && !sawOwned {
		return accessPlan{}, nil
	}

	// auto-pagination engages only when both PerPage and Page are zero, do NOT
	// copy the Page/PerPage workaround from bootstrap.go: here it would
	// silently truncate the list, and a missing owned application looks like an
	// absent one, producing duplicate creates and un-reaped orphans
	applications, _, err := t.cfClient.ListAccessApplications(ctx, cloudflare.AccountIdentifier(t.accountId), cloudflare.ListAccessApplicationsParams{})
	if err != nil {
		metrics.CloudflareAPIErrors.WithLabelValues("list_access_applications").Inc()
		if !wanted {
			// nothing is being published that needs protection, so deferring
			// the reaping to the next reconcile costs nothing and holding DNS
			// hostage for the whole cluster costs everything
			t.logger.Error(err, "list access applications failed while no exposure requests Access, continuing the sync")
			return accessPlan{}, nil
		}
		return accessPlan{}, errors.Wrap(err, "list access applications")
	}

	creates, updates, deletes, quarantined, managed, err := syncAccessApplications(
		t.logger, exposures, applications, t.tunnelName, t.tunnelId, t.access,
	)
	if err != nil {
		return accessPlan{}, errors.Wrap(err, "sync access applications")
	}

	t.accessMutex.Lock()
	t.accessListedOnce = true
	// the creates of this pass count too, the latch is read by the next
	// reconcile and by then they exist and are owned
	t.sawOwnedApplications = sawOwnedApplications(applications, creates, t.tunnelName, t.tunnelId)
	t.accessMutex.Unlock()

	t.logger.V(3).Info("sync access applications", "to-create", creates, "to-update", updates, "to-delete", deletes, "quarantined", quarantined)

	return accessPlan{
		creates:     creates,
		updates:     updates,
		deletes:     deletes,
		quarantined: quarantined,
		managed:     managed,
	}, nil
}

// applyAccessUpserts applies the creations and updates only.
func (t *TunnelClient) applyAccessUpserts(ctx context.Context, plan accessPlan) error {
	// updates carry tags too: migrating an application from the tunnel id form
	// tag to the name form sends a tag name the account has never seen, with no
	// create anywhere in the plan to have made it
	if len(plan.creates)+len(plan.updates) > 0 {
		if err := t.ensureOwnershipTags(ctx); err != nil {
			return errors.Wrap(err, "ensure ownership tags")
		}
	}

	for _, item := range plan.creates {
		t.logger.Info("create access application", "hostname", item.Spec.Hostname, "policies", item.Spec.Policies)
		_, err := t.cfClient.CreateAccessApplication(ctx, cloudflare.AccountIdentifier(t.accountId), accessCreateParams(item.Spec))
		if err != nil {
			metrics.CloudflareAPIErrors.WithLabelValues("create_access_application").Inc()
			return errors.Wrapf(err, "create access application for hostname %s", item.Spec.Hostname)
		}
		metrics.AccessApplicationOperations.WithLabelValues("create").Inc()
	}

	for _, item := range plan.updates {
		t.logger.Info("update access application", "id", item.OldApplication.ID, "hostname", item.Spec.Hostname, "policies", item.Spec.Policies)
		_, err := t.cfClient.UpdateAccessApplication(ctx, cloudflare.AccountIdentifier(t.accountId), accessUpdateParams(item))
		if err != nil {
			metrics.CloudflareAPIErrors.WithLabelValues("update_access_application").Inc()
			return errors.Wrapf(err, "update access application for hostname %s", item.Spec.Hostname)
		}
		metrics.AccessApplicationOperations.WithLabelValues("update").Inc()
	}

	return nil
}

// applyAccessDeletes applies the deletions only. Withdrawn deletions are gated
// on removedHostnames, the set of hostnames whose CNAME this pass positively
// removed or observed absent. Opted out deletions are not gated: the hostname
// is deliberately still routable and the operator explicitly asked for the
// protection to come off.
func (t *TunnelClient) applyAccessDeletes(ctx context.Context, plan accessPlan, removedHostnames map[string]struct{}) error {
	for _, item := range plan.deletes {
		hostname := strings.ToLower(item.OldApplication.Domain)

		if item.Reason == AccessDeleteReasonWithdrawn {
			if _, removed := removedHostnames[hostname]; !removed {
				// the CNAME was relinquished to a third party who is now
				// serving the hostname, keeping the application protects it
				t.logger.Info("WARNING: access application retained, its DNS record was not confirmed gone",
					"hostname", hostname, "id", item.OldApplication.ID,
				)
				metrics.AccessApplicationOperations.WithLabelValues("retained").Inc()
				continue
			}
		}

		// removing an Access application makes a hostname public again, that
		// transition deserves a warning, not an info
		t.logger.Info("WARNING: delete access application, the hostname is no longer protected by this controller",
			"hostname", hostname, "id", item.OldApplication.ID, "reason", item.Reason,
		)
		err := t.cfClient.DeleteAccessApplication(ctx, cloudflare.AccountIdentifier(t.accountId), item.OldApplication.ID)
		if err != nil {
			metrics.CloudflareAPIErrors.WithLabelValues("delete_access_application").Inc()
			return errors.Wrapf(err, "delete access application for hostname %s", hostname)
		}
		metrics.AccessApplicationOperations.WithLabelValues("delete").Inc()
	}
	return nil
}

// ensureOwnershipTags creates the two ownership tags if the account does not
// carry them yet. It runs lazily, immediately before the first create, so an
// install that never creates an application pays nothing for it.
func (t *TunnelClient) ensureOwnershipTags(ctx context.Context) error {
	t.accessMutex.Lock()
	defer t.accessMutex.Unlock()
	if t.ownershipTagsEnsured {
		return nil
	}

	existing, err := t.cfClient.ListAccessTags(ctx, cloudflare.AccountIdentifier(t.accountId), cloudflare.ListAccessTagsParams{})
	if err != nil {
		metrics.CloudflareAPIErrors.WithLabelValues("list_access_tags").Inc()
		return errors.Wrap(err, "list access tags")
	}

	var names []string
	for _, tag := range existing {
		names = append(names, tag.Name)
	}

	for _, tag := range ownershipTags(t.tunnelName) {
		if slices.Contains(names, tag) {
			continue
		}
		t.logger.Info("create access tag", "tag", tag)
		if _, err := t.cfClient.CreateAccessTag(ctx, cloudflare.AccountIdentifier(t.accountId), cloudflare.CreateAccessTagParams{Name: tag}); err != nil {
			metrics.CloudflareAPIErrors.WithLabelValues("create_access_tag").Inc()
			return errors.Wrapf(err, "create access tag %s", tag)
		}
	}

	t.ownershipTagsEnsured = true
	return nil
}

func (t *TunnelClient) TunnelDomain() string {
	return tunnelDomain(t.tunnelId)
}

func (t *TunnelClient) updateTunnelIngressRules(ctx context.Context, exposures []exposure.Exposure) error {
	var ingressRules []cloudflare.UnvalidatedIngressRule

	effectiveExposures := exposure.Active(exposures)

	for _, item := range effectiveExposures {
		ingress, err := fromExposureToCloudflareIngress(ctx, item)
		if err != nil {
			return errors.Wrapf(err, "transform to cloudflare ingress")
		}
		ingressRules = append(ingressRules, *ingress)
	}

	// sort the rules: non-wildcard hostnames before wildcard hostnames (wildcards are fallbacks),
	// then alphabetically by hostname, then by path length in descending order
	// to ensure "precedence will be given first to the longest matching path".
	slices.SortFunc(ingressRules, sortIngressRules)

	// at last, append a default 404 service as default route
	ingressRules = append(ingressRules, cloudflare.UnvalidatedIngressRule{
		Service: "http_status:404",
	})

	t.logger.V(3).Info("update cloudflare tunnel config", "ingress-rules", ingressRules)

	current, err := t.cfClient.GetTunnelConfiguration(ctx, cloudflare.ResourceIdentifier(t.accountId), t.tunnelId)
	if err != nil {
		metrics.CloudflareAPIErrors.WithLabelValues("get_tunnel_configuration").Inc()
		return errors.Wrap(err, "get cloudflare tunnel config")
	}

	if reflect.DeepEqual(current.Config.Ingress, ingressRules) {
		t.logger.Info("cloudflare tunnel config unchanged, skipping update")
		return nil
	}

	_, err = t.cfClient.UpdateTunnelConfiguration(ctx,
		cloudflare.ResourceIdentifier(t.accountId),
		cloudflare.TunnelConfigurationParams{
			TunnelID: t.tunnelId,
			Config: cloudflare.TunnelConfiguration{
				Ingress: ingressRules,
			},
		},
	)

	if err != nil {
		metrics.CloudflareAPIErrors.WithLabelValues("update_tunnel_configuration").Inc()
		return errors.Wrap(err, "update cloudflare tunnel config")
	}
	return nil
}

// updateDNSCNAMERecord reconciles the CNAME and ownership TXT records and
// reports back which of the hostnames in interested it positively removed or
// positively observed to be absent. A hostname whose zone this pass never
// listed is never reported: the caller must treat "not reported" as "still
// possibly resolving", which is the fail-closed direction.
func (t *TunnelClient) updateDNSCNAMERecord(ctx context.Context, exposures []exposure.Exposure, interested map[string]struct{}) (map[string]struct{}, error) {
	removed := make(map[string]struct{})

	t.logger.V(3).Info("list zones")
	zones, err := t.cfClient.ListZones(ctx)
	if err != nil {
		metrics.CloudflareAPIErrors.WithLabelValues("list_zones").Inc()
		return removed, errors.Wrap(err, "list cloudflare zones")
	}

	var zoneNames []string
	for _, zone := range zones {
		zoneNames = append(zoneNames, zone.Name)
	}
	t.logger.V(3).Info("zones", "zones", zoneNames)

	interestedByZone := interestedHostnamesByZone(interested, zoneNames)

	var exposuresByZone = make(map[string][]exposure.Exposure)
	for _, item := range exposures {
		ok, zone := zoneBelongedByExposure(item, zoneNames)
		if ok {
			exposuresByZone[zone] = append(exposuresByZone[zone], item)
		} else if item.DisableDNSManagement {
			// DNS management is delegated externally for this exposure; its hostname
			// may live in a zone not managed by this Cloudflare account, so don't
			// require a zone match and skip it from DNS reconciliation.
			t.logger.V(3).Info("DNS management disabled for exposure, skipping DNS reconciliation", "hostname", item.Hostname)
			continue
		} else {
			return removed, errors.Errorf("hostname %s not belong to any zone", item.Hostname)
		}
	}

	for zoneName, items := range exposuresByZone {
		ok, zone := findZoneByName(zoneName, zones)
		if !ok {
			return removed, errors.Errorf("zone %s not found", zoneName)
		}
		removedInZone, err := t.updateDNSCNAMERecordForZone(ctx, items, zone, interestedByZone[zoneName])
		if err != nil {
			return removed, errors.Wrapf(err, "update DNS CNAME record for zone %s", zoneName)
		}
		delete(interestedByZone, zoneName)
		maps.Copy(removed, removedInZone)
	}

	// A zone that just lost its last exposure still has to be visited. Without
	// this pass its orphaned records are never reaped, so the removal signal
	// keeps reporting the hostname as still served and its Access application is
	// retained forever.
	for _, zoneName := range slices.Sorted(maps.Keys(interestedByZone)) {
		ok, zone := findZoneByName(zoneName, zones)
		if !ok {
			return removed, errors.Errorf("zone %s not found", zoneName)
		}
		removedInZone, err := t.updateDNSCNAMERecordForZone(ctx, nil, zone, interestedByZone[zoneName])
		if err != nil {
			return removed, errors.Wrapf(err, "update DNS CNAME record for zone %s", zoneName)
		}
		maps.Copy(removed, removedInZone)
	}
	return removed, nil
}

func (t *TunnelClient) updateDNSCNAMERecordForZone(ctx context.Context, exposures []exposure.Exposure, zone cloudflare.Zone, interested []string) (map[string]struct{}, error) {
	// One listing of every record type instead of one per type. The removal
	// signal has to know whether ANY record still answers for an interested
	// hostname: a hostname repointed to an A record still resolves, and looking
	// only at CNAMEs would report it removed and strip its Access application.
	allDnsRecords, _, err := t.cfClient.ListDNSRecords(ctx, cloudflare.ResourceIdentifier(zone.ID), cloudflare.ListDNSRecordsParams{})
	if err != nil {
		metrics.CloudflareAPIErrors.WithLabelValues("list_dns_records").Inc()
		return nil, errors.Wrapf(err, "list DNS records for zone %s", zone.Name)
	}

	var cnameDnsRecords []cloudflare.DNSRecord
	var txtDnsRecords []cloudflare.DNSRecord
	for _, record := range allDnsRecords {
		switch {
		case record.Type == "CNAME":
			cnameDnsRecords = append(cnameDnsRecords, record)
		// only the ownership TXT records this controller writes
		case record.Type == "TXT" && strings.HasPrefix(record.Name, ManagedRecordTXTPrefix+"."):
			txtDnsRecords = append(txtDnsRecords, record)
		}
	}

	toCreate, toUpdate, toDelete, err := syncDNSRecord(t.logger, exposures, cnameDnsRecords, txtDnsRecords, t.tunnelId, t.tunnelName)
	if err != nil {
		return nil, errors.Wrap(err, "sync DNS records")
	}
	t.logger.V(3).Info("sync DNS records", "to-create", toCreate, "to-update", toUpdate, "to-delete", toDelete)

	for _, item := range toCreate {
		t.logger.Info("create DNS record", "type", item.Type, "hostname", item.Hostname, "content", item.Content)
		params := cloudflare.CreateDNSRecordParams{
			Type:    item.Type,
			Name:    item.Hostname,
			Content: item.Content,
			Proxied: cloudflare.BoolPtr(item.Type == "CNAME"),
			TTL:     1,
		}
		// Add comment to every managed record if template is configured.
		// Comments are informational only; ownership is tracked via TXT record content.
		// See https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/
		if comment := t.renderDNSComment(item.Hostname); comment != "" {
			params.Comment = comment
		}
		_, err := t.cfClient.CreateDNSRecord(ctx, cloudflare.ResourceIdentifier(zone.ID), params)
		if err != nil {
			metrics.CloudflareAPIErrors.WithLabelValues("create_dns_record").Inc()
			return nil, errors.Wrapf(err, "create DNS record for zone %s, hostname %s", zone.Name, item.Hostname)
		}
		metrics.DNSRecordOperations.WithLabelValues("create", item.Type).Inc()
	}

	for _, item := range toUpdate {
		t.logger.Info("update DNS record", "id", item.OldRecord.ID, "type", item.Type, "hostname", item.OldRecord.Name, "content", item.Content)
		params := cloudflare.UpdateDNSRecordParams{
			ID:      item.OldRecord.ID,
			Type:    item.Type,
			Name:    item.OldRecord.Name,
			Content: item.Content,
			Proxied: cloudflare.BoolPtr(item.Type == "CNAME"),
			TTL:     1,
		}
		// Add comment to every managed record if template is configured.
		if comment := t.renderDNSComment(item.OldRecord.Name); comment != "" {
			params.Comment = &comment
		}
		_, err := t.cfClient.UpdateDNSRecord(ctx, cloudflare.ResourceIdentifier(zone.ID), params)
		if err != nil {
			metrics.CloudflareAPIErrors.WithLabelValues("update_dns_record").Inc()
			return nil, errors.Wrapf(err, "update DNS record for zone %s, hostname %s", zone.Name, item.OldRecord.Name)
		}
		metrics.DNSRecordOperations.WithLabelValues("update", item.Type).Inc()
	}

	// Migrate legacy comment-based records (separate from normal sync)
	legacyDeletes, err := migrateLegacyDNSRecords(t.logger, exposures, cnameDnsRecords, txtDnsRecords, t.tunnelName)
	if err != nil {
		return nil, errors.Wrap(err, "migrate legacy DNS records")
	}
	toDelete = append(toDelete, legacyDeletes...)

	for _, item := range toDelete {
		t.logger.Info("delete DNS record", "id", item.OldRecord.ID, "type", item.OldRecord.Type, "hostname", item.OldRecord.Name, "content", item.OldRecord.Content)
		err := t.cfClient.DeleteDNSRecord(ctx, cloudflare.ResourceIdentifier(zone.ID), item.OldRecord.ID)
		if err != nil {
			metrics.CloudflareAPIErrors.WithLabelValues("delete_dns_record").Inc()
			return nil, errors.Wrapf(err, "delete DNS record for zone %s, hostname %s", zone.Name, item.OldRecord.Name)
		}
		metrics.DNSRecordOperations.WithLabelValues("delete", item.OldRecord.Type).Inc()
	}

	// report back which of this zone's interested hostnames the pass positively
	// cleared. "the DNS step returned nil" is not the same statement: the
	// relinquish path deliberately keeps a CNAME a third party repointed.
	return removedHostnamesInZone(interested, allDnsRecords, toDelete), nil
}

// interestedHostnamesByZone buckets every hostname whose DNS removal the caller
// wants to know about under the single zone that answers for it, the same
// resolution the record itself was created under.
//
// One zone per hostname is the whole point. Asking every zone whose name is a
// suffix of the hostname is what let a zone that never held the record report
// it gone: with a parent zone and a subdomain zone in one account, the parent
// finds no record for a hostname the child zone still serves, and the Access
// application is then deleted off a hostname that still resolves.
//
// A hostname no zone in the account answers for is dropped, and the caller
// reads its absence from the result as "it may still resolve".
func interestedHostnamesByZone(interested map[string]struct{}, zoneNames []string) map[string][]string {
	byZone := make(map[string][]string)
	for hostname := range interested {
		ok, zoneName := zoneForHostname(hostname, zoneNames)
		if !ok {
			continue
		}
		byZone[zoneName] = append(byZone[zoneName], hostname)
	}
	// map iteration order is not an order, and these drive API calls
	for _, hostnames := range byZone {
		slices.Sort(hostnames)
	}
	return byZone
}

// removedHostnamesInZone reports which of this zone's interested hostnames it
// no longer serves once the planned deletions have been applied.
//
// A hostname counts as removed only when no record of any type is left for it.
// Anything short of that is left out of the result, and the caller reads a
// hostname's absence from the result as "it may still resolve", so every
// uncertainty resolves in the fail-closed direction: the Access application in
// front of the hostname is retained rather than removed.
func removedHostnamesInZone(interested []string, records []cloudflare.DNSRecord, deleted []DNSOperationDelete) map[string]struct{} {
	removed := make(map[string]struct{})
	if len(interested) == 0 {
		return removed
	}

	deletedIDs := make(map[string]struct{}, len(deleted))
	for _, item := range deleted {
		if item.OldRecord.ID == "" {
			continue
		}
		deletedIDs[item.OldRecord.ID] = struct{}{}
	}

	surviving := make(map[string]struct{}, len(records))
	for _, record := range records {
		if _, wasDeleted := deletedIDs[record.ID]; wasDeleted {
			continue
		}
		surviving[strings.ToLower(record.Name)] = struct{}{}
	}

	for _, hostname := range interested {
		if _, stillServed := surviving[strings.ToLower(hostname)]; !stillServed {
			removed[strings.ToLower(hostname)] = struct{}{}
		}
	}
	return removed
}

// zoneForHostname resolves a hostname to the single zone that answers for it.
// One zone, never several: two zones in one account can both suffix-match a
// hostname when one is a subdomain zone of the other, and consulting both lets
// the zone that never held the record decide it is gone.
//
// Which one of several matches wins is the longest zone name, not the first in
// ListZones order. Cloudflare answers a name from the most specific zone that
// covers it, so a hostname under a child zone lives in the child zone even when
// the parent is listed first, and resolving it to the parent would look in a
// zone that never held the record.
func zoneForHostname(hostname string, zones []string) (bool, string) {
	hostnameDomain := Domain{Name: hostname}

	found := false
	best := ""
	for _, zone := range zones {
		zoneDomain := Domain{Name: zone}
		if !hostnameDomain.IsSubDomainOf(zoneDomain) && hostnameDomain.Name != zoneDomain.Name {
			continue
		}
		if !found || len(zone) > len(best) {
			found = true
			best = zone
		}
	}
	return found, best
}

func zoneBelongedByExposure(exposure exposure.Exposure, zones []string) (bool, string) {
	return zoneForHostname(exposure.Hostname, zones)
}

func findZoneByName(zoneName string, zones []cloudflare.Zone) (bool, cloudflare.Zone) {
	for _, zone := range zones {
		if zone.Name == zoneName {
			return true, zone
		}
	}
	return false, cloudflare.Zone{}
}

func (t *TunnelClient) FetchTunnelToken(ctx context.Context) (string, error) {
	return t.cfClient.GetTunnelToken(ctx, cloudflare.ResourceIdentifier(t.accountId), t.tunnelId)
}

// sortIngressRules defines the sort order for Cloudflare tunnel ingress rules:
// non-wildcard hostnames before wildcard hostnames (wildcards act as fallbacks),
// then alphabetically by hostname, then by path length in descending order.
func sortIngressRules(a, b cloudflare.UnvalidatedIngressRule) int {
	aIsWildcard := strings.HasPrefix(a.Hostname, "*.")
	bIsWildcard := strings.HasPrefix(b.Hostname, "*.")
	if aIsWildcard != bIsWildcard {
		if aIsWildcard {
			return 1
		}
		return -1
	}
	// a broader wildcard suffix-matches everything a more specific one
	// covers, so wildcards with more labels must come first:
	// *.internal.example.com before *.example.com
	if aIsWildcard {
		if v := strings.Count(b.Hostname, ".") - strings.Count(a.Hostname, "."); v != 0 {
			return v
		}
	}
	if v := strings.Compare(strings.ToLower(a.Hostname), strings.ToLower(b.Hostname)); v != 0 {
		return v
	}
	if v := len(b.Path) - len(a.Path); v != 0 {
		return v
	}
	// lexical fallback keeps the comparator a total order, the rule list
	// must be deterministic or reconciles would push spurious updates
	return strings.Compare(a.Path, b.Path)
}
