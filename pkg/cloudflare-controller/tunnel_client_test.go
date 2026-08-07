package cloudflarecontroller

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/exposure"
	"github.com/cloudflare/cloudflare-go"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
)

func TestRenderDNSComment(t *testing.T) {
	tests := []struct {
		name              string
		templateStr       string
		hostname          string
		tunnelName        string
		tunnelId          string
		wantContains      string
		wantEmpty         bool
		wantLengthOver100 bool
	}{
		{
			name:        "empty template disables comments",
			templateStr: "",
			hostname:    "app.example.com",
			wantEmpty:   true,
		},
		{
			name:         "default template renders correctly",
			templateStr:  "managed by cloudflare-tunnel-ingress-controller, tunnel [{{.TunnelName}}]",
			hostname:     "app.example.com",
			tunnelName:   "my-tunnel",
			tunnelId:     "abc-123",
			wantContains: "managed by cloudflare-tunnel-ingress-controller, tunnel [my-tunnel]",
		},
		{
			name:         "template with all variables",
			templateStr:  "tunnel={{.TunnelName}} id={{.TunnelId}} host={{.Hostname}}",
			hostname:     "app.example.com",
			tunnelName:   "my-tunnel",
			tunnelId:     "abc-123",
			wantContains: "tunnel=my-tunnel id=abc-123 host=app.example.com",
		},
		{
			name:         "template with only hostname",
			templateStr:  "record for {{.Hostname}}",
			hostname:     "sub.domain.example.com",
			tunnelName:   "t",
			tunnelId:     "id",
			wantContains: "record for sub.domain.example.com",
		},
		{
			name:              "long comment exceeds 100 chars",
			templateStr:       "this is a very long comment template that will definitely exceed one hundred characters when rendered with tunnel={{.TunnelName}}",
			hostname:          "app.example.com",
			tunnelName:        "my-long-tunnel-name",
			tunnelId:          "abc-123",
			wantLengthOver100: true,
		},
		{
			name:        "invalid template syntax degrades gracefully",
			templateStr: "{{.InvalidSyntax",
			hostname:    "app.example.com",
			wantEmpty:   true,
		},
		{
			name:         "static template without variables",
			templateStr:  "managed by controller",
			hostname:     "app.example.com",
			tunnelName:   "t",
			tunnelId:     "id",
			wantContains: "managed by controller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := NewTunnelClient(logr.Discard(), nil, "acc", tt.tunnelId, tt.tunnelName, tt.templateStr, exposure.AccessDefaults{})
			got := tc.renderDNSComment(tt.hostname)

			if tt.wantEmpty && got != "" {
				t.Errorf("expected empty comment, got %q", got)
			}
			if tt.wantContains != "" && got != tt.wantContains {
				t.Errorf("expected %q, got %q", tt.wantContains, got)
			}
			if tt.wantLengthOver100 && len(got) <= 100 {
				t.Errorf("expected comment length > 100, got %d: %q", len(got), got)
			}
			if !tt.wantEmpty && tt.wantContains != "" && strings.TrimSpace(got) == "" {
				t.Errorf("expected non-empty comment, got empty")
			}
		})
	}
}

func Test_sortIngressRules(t *testing.T) {
	tests := []struct {
		name      string
		input     []cloudflare.UnvalidatedIngressRule
		wantOrder []cloudflare.UnvalidatedIngressRule
	}{
		{
			name: "wildcard sorts after explicit hostname",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.example.com", Path: "/"},
				{Hostname: "app.example.com", Path: "/"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "app.example.com", Path: "/"},
				{Hostname: "*.example.com", Path: "/"},
			},
		},
		{
			name: "multiple explicit hostnames before wildcard",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.example.com", Path: "/"},
				{Hostname: "app.example.com", Path: "/"},
				{Hostname: "api.example.com", Path: "/"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "api.example.com", Path: "/"},
				{Hostname: "app.example.com", Path: "/"},
				{Hostname: "*.example.com", Path: "/"},
			},
		},
		{
			name: "non-wildcard only sorts alphabetically",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "z.example.com", Path: "/"},
				{Hostname: "a.example.com", Path: "/"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "a.example.com", Path: "/"},
				{Hostname: "z.example.com", Path: "/"},
			},
		},
		{
			name: "path length descending for same hostname",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "app.example.com", Path: "/"},
				{Hostname: "app.example.com", Path: "/longer/path"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "app.example.com", Path: "/longer/path"},
				{Hostname: "app.example.com", Path: "/"},
			},
		},
		{
			name: "equal length paths order lexically",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "app.example.com", Path: "/foo"},
				{Hostname: "app.example.com", Path: "/api"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "app.example.com", Path: "/api"},
				{Hostname: "app.example.com", Path: "/foo"},
			},
		},
		{
			name: "single character subdomain sorts before wildcard",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.example.com", Path: "/"},
				{Hostname: "x.example.com", Path: "/"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "x.example.com", Path: "/"},
				{Hostname: "*.example.com", Path: "/"},
			},
		},
		{
			name: "apex domain sorts before its wildcard",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.example.com", Path: "/"},
				{Hostname: "example.com", Path: "/"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "example.com", Path: "/"},
				{Hostname: "*.example.com", Path: "/"},
			},
		},
		{
			name: "more specific wildcard sorts before broader wildcard",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.example.com", Path: "/"},
				{Hostname: "*.internal.example.com", Path: "/"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.internal.example.com", Path: "/"},
				{Hostname: "*.example.com", Path: "/"},
			},
		},
		{
			name: "wildcards with equal specificity sort alphabetically",
			input: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.b.example.com", Path: "/"},
				{Hostname: "*.a.example.com", Path: "/"},
			},
			wantOrder: []cloudflare.UnvalidatedIngressRule{
				{Hostname: "*.a.example.com", Path: "/"},
				{Hostname: "*.b.example.com", Path: "/"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := make([]cloudflare.UnvalidatedIngressRule, len(tt.input))
			copy(rules, tt.input)

			slices.SortFunc(rules, sortIngressRules)

			for i, rule := range rules {
				if rule.Hostname != tt.wantOrder[i].Hostname || rule.Path != tt.wantOrder[i].Path {
					t.Errorf("position %d: got %s%s, want %s%s", i, rule.Hostname, rule.Path, tt.wantOrder[i].Hostname, tt.wantOrder[i].Path)
				}
			}
		})
	}
}

func Test_withoutQuarantined(t *testing.T) {
	exposures := []exposure.Exposure{
		{Hostname: "keep.example.com", PathPrefix: "/"},
		{Hostname: "Drop.Example.COM", PathPrefix: "/"},
		{Hostname: "drop.example.com", PathPrefix: "/api"},
	}

	if got := withoutQuarantined(exposures, nil); len(got) != 3 {
		t.Errorf("withoutQuarantined() with nothing quarantined = %d exposures, want 3", len(got))
	}

	got := withoutQuarantined(exposures, map[string]string{"drop.example.com": "whatever"})
	if len(got) != 1 || got[0].Hostname != "keep.example.com" {
		t.Errorf("withoutQuarantined() = %v, want only keep.example.com", got)
	}
}

func Test_withdrawnHostnames(t *testing.T) {
	plan := accessPlan{
		deletes: []AccessOperationDelete{
			{OldApplication: cloudflare.AccessApplication{Domain: "withdrawn.example.com"}, Reason: AccessDeleteReasonWithdrawn},
			{OldApplication: cloudflare.AccessApplication{Domain: "OptedOut.Example.COM"}, Reason: AccessDeleteReasonOptedOut},
		},
	}

	got := withdrawnHostnames(plan)
	// only withdrawn deletions are gated on a DNS removal signal, an opted out
	// hostname is deliberately still routable
	want := map[string]struct{}{"withdrawn.example.com": {}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("withdrawnHostnames() = %v, want %v", got, want)
	}
}

// reachedCloudflare reports whether fn started a Cloudflare API call.
//
// The client under test holds a nil *cloudflare.API, so the first real call
// panics inside the SDK. Recovering turns "it made a call" into an assertion,
// which is what lets a test state the negative: with Access disabled, or with
// nothing to do, no Access API call happens at all.
func reachedCloudflare(fn func() error) (called bool) {
	defer func() {
		if recover() != nil {
			called = true
		}
	}()
	_ = fn()
	return false
}

// accessTestClient is a client whose every Cloudflare call panics, see
// reachedCloudflare.
func accessTestClient(access exposure.AccessDefaults) *TunnelClient {
	return NewTunnelClient(logr.Discard(), nil, "account-id", "tunnel-id", WhateverTunnelName, "", access)
}

func Test_accessDisabledMakesNoCloudflareCall(t *testing.T) {
	// the headline backwards compatibility guarantee: an installation that does
	// not opt in sees no new API call, no new token scope, no new failure mode
	client := accessTestClient(exposure.AccessDefaults{Policies: []string{"8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b40"}})
	exposures := []exposure.Exposure{accessEnabledExposure(WhateverHostname)}

	if reachedCloudflare(func() error { return client.validateAccessPolicies(t.Context()) }) {
		t.Error("validateAccessPolicies() called Cloudflare while access is disabled")
	}
	if reachedCloudflare(func() error {
		_, err := client.planAccessApplications(t.Context(), exposures)
		return err
	}) {
		t.Error("planAccessApplications() called Cloudflare while access is disabled")
	}
	if reachedCloudflare(func() error {
		return client.applyAccessUpserts(t.Context(), accessPlan{})
	}) {
		t.Error("applyAccessUpserts() called Cloudflare for an empty plan")
	}
	if reachedCloudflare(func() error {
		return client.applyAccessDeletes(t.Context(), accessPlan{}, nil)
	}) {
		t.Error("applyAccessDeletes() called Cloudflare for an empty plan")
	}
}

func Test_planAccessApplicationsListSkipRule(t *testing.T) {
	enabled := exposure.AccessDefaults{Enabled: true}
	plain := []exposure.Exposure{{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.1:233", PathPrefix: "/"}}
	wantsAccess := []exposure.Exposure{accessEnabledExposure(WhateverHostname)}

	listed := func(client *TunnelClient, exposures []exposure.Exposure) bool {
		return reachedCloudflare(func() error {
			_, err := client.planAccessApplications(t.Context(), exposures)
			return err
		})
	}

	// enabling the chart flag on its own must not add a per reconcile API call
	skipping := accessTestClient(enabled)
	skipping.accessListedOnce = true
	if listed(skipping, plain) {
		t.Error("planAccessApplications() listed applications with nothing annotated and nothing owned")
	}

	// the first reconcile of the process always lists, an application whose
	// annotation was removed while the pod was down still has to be reaped
	if !listed(accessTestClient(enabled), plain) {
		t.Error("planAccessApplications() skipped the first listing of the process")
	}

	// an exposure asking for Access is never skipped
	if !listed(skipping, wantsAccess) {
		t.Error("planAccessApplications() skipped the listing while an exposure requests Access")
	}

	// still owning an application keeps the reverse pass alive. This is the
	// state the latch has to reach after the pass that creates the first
	// application, or the documented opt-out silently stops reaping
	owning := accessTestClient(enabled)
	owning.accessListedOnce = true
	owning.sawOwnedApplications = sawOwnedApplications(nil, []AccessOperationCreate{{Spec: AccessApplicationSpec{Hostname: WhateverHostname}}}, WhateverTunnelName, "tunnel-id")
	if !listed(owning, plain) {
		t.Error("planAccessApplications() skipped the listing while this controller still owns an application")
	}
}

func Test_applyAccessDeletesGate(t *testing.T) {
	client := accessTestClient(exposure.AccessDefaults{Enabled: true})
	withdrawn := accessPlan{deletes: []AccessOperationDelete{{
		OldApplication: cloudflare.AccessApplication{ID: "app-1", Domain: "Withdrawn.Example.COM"},
		Reason:         AccessDeleteReasonWithdrawn,
	}}}
	optedOut := accessPlan{deletes: []AccessOperationDelete{{
		OldApplication: cloudflare.AccessApplication{ID: "app-2", Domain: "opted-out.example.com"},
		Reason:         AccessDeleteReasonOptedOut,
	}}}

	// the DNS pass did not confirm the record gone: something is still serving
	// the hostname, and removing its Access application would make whatever
	// that is public
	if reachedCloudflare(func() error { return client.applyAccessDeletes(t.Context(), withdrawn, map[string]struct{}{}) }) {
		t.Error("applyAccessDeletes() deleted a withdrawn application whose DNS record was not confirmed gone")
	}
	// a different hostname being gone says nothing about this one
	if reachedCloudflare(func() error {
		return client.applyAccessDeletes(t.Context(), withdrawn, map[string]struct{}{"other.example.com": {}})
	}) {
		t.Error("applyAccessDeletes() deleted a withdrawn application on another hostname's removal signal")
	}
	// confirmed gone, so the application is an orphan and has to be reaped
	if !reachedCloudflare(func() error {
		return client.applyAccessDeletes(t.Context(), withdrawn, map[string]struct{}{"withdrawn.example.com": {}})
	}) {
		t.Error("applyAccessDeletes() retained a withdrawn application whose DNS record is confirmed gone")
	}
	// opting out is an explicit operator decision to make the hostname public
	// again, it is deliberately not gated on anything
	if !reachedCloudflare(func() error { return client.applyAccessDeletes(t.Context(), optedOut, map[string]struct{}{}) }) {
		t.Error("applyAccessDeletes() gated an opted out deletion on the DNS removal signal")
	}
}

func Test_validateAccessPoliciesListingSucceeds(t *testing.T) {
	const configured = "8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b40"
	client := accessTestClient(exposure.AccessDefaults{Enabled: true, Policies: []string{configured}})

	// the §7 criterion: a configured ID the account does not have is a settled
	// fact about the configuration, so the pod refuses to start and says which
	calls := 0
	absent := func(context.Context) ([]cloudflare.AccessPolicy, error) {
		calls++
		return []cloudflare.AccessPolicy{{ID: "3f0b5a11-8c47-4d2e-9a63-1e8f4c7d2a05"}}, nil
	}
	err := client.validateAccessPoliciesWith(t.Context(), absent, 3, 0)
	if err == nil {
		t.Fatal("validateAccessPoliciesWith() accepted a policy ID the successful listing did not contain")
	}
	if !strings.Contains(err.Error(), configured) {
		t.Errorf("validateAccessPoliciesWith() error = %q, want it to name %q", err, configured)
	}
	if calls != 1 {
		t.Errorf("validateAccessPoliciesWith() listed %d time(s) for a successful call, want 1", calls)
	}

	// present, so startup proceeds
	present := func(context.Context) ([]cloudflare.AccessPolicy, error) {
		return []cloudflare.AccessPolicy{{ID: configured}}, nil
	}
	if err := client.validateAccessPoliciesWith(t.Context(), present, 3, 0); err != nil {
		t.Errorf("validateAccessPoliciesWith() = %v, want nil for a configured policy the account has", err)
	}
}

func Test_validateAccessPoliciesListingErrors(t *testing.T) {
	const configured = "8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b40"
	client := accessTestClient(exposure.AccessDefaults{Enabled: true, Policies: []string{configured}})

	// a listing that never succeeds must not take the whole cluster's DNS down:
	// the startup check is an early warning, the plan time quarantine and the
	// create time failure are the actual safety mechanisms
	calls := 0
	failing := func(context.Context) ([]cloudflare.AccessPolicy, error) {
		calls++
		return nil, errors.New("HTTP status 403: Actor does not have permission to read access policies")
	}
	if err := client.validateAccessPoliciesWith(t.Context(), failing, 3, 0); err != nil {
		t.Errorf("validateAccessPoliciesWith() = %v, want nil so the controller starts with the policy IDs unverified", err)
	}
	if calls != 3 {
		t.Errorf("validateAccessPoliciesWith() made %d attempt(s), want 3", calls)
	}

	// a transient error is ridden out, and the recovered listing is still
	// validated rather than waved through
	calls = 0
	flaky := func(context.Context) ([]cloudflare.AccessPolicy, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("HTTP status 502: Bad Gateway")
		}
		return []cloudflare.AccessPolicy{{ID: "3f0b5a11-8c47-4d2e-9a63-1e8f4c7d2a05"}}, nil
	}
	if err := client.validateAccessPoliciesWith(t.Context(), flaky, 3, 0); err == nil {
		t.Error("validateAccessPoliciesWith() accepted an absent policy ID after the listing recovered")
	}
	if calls != 3 {
		t.Errorf("validateAccessPoliciesWith() made %d attempt(s) before the listing recovered, want 3", calls)
	}

	// nothing configured means nothing to verify, and no API call at all
	quiet := accessTestClient(exposure.AccessDefaults{Enabled: true})
	if reachedCloudflare(func() error { return quiet.validateAccessPolicies(t.Context()) }) {
		t.Error("validateAccessPolicies() called Cloudflare with no policies configured")
	}
}

func Test_zoneForHostname(t *testing.T) {
	// a subdomain zone alongside its parent, the shape that made the removal
	// signal lie: both zones suffix match, and only one of them holds the record
	zones := []string{"sub.example.com", "example.com"}

	if ok, zone := zoneForHostname("a.sub.example.com", zones); !ok || zone != "sub.example.com" {
		t.Errorf("zoneForHostname() = %v %q, want true sub.example.com", ok, zone)
	}
	if ok, zone := zoneForHostname("a.example.com", zones); !ok || zone != "example.com" {
		t.Errorf("zoneForHostname() = %v %q, want true example.com", ok, zone)
	}
	if ok, zone := zoneForHostname("example.com", zones); !ok || zone != "example.com" {
		t.Errorf("zoneForHostname() = %v %q, want true example.com", ok, zone)
	}
	// a hostname no zone in the account answers for is never resolved, and the
	// caller reads that as "it may still resolve"
	if ok, _ := zoneForHostname("app.elsewhere.com", zones); ok {
		t.Error("zoneForHostname() resolved a hostname outside every zone")
	}
	// the resolution the DNS records were created under, unchanged
	item := exposure.Exposure{Hostname: "a.sub.example.com"}
	okExposure, zoneExposure := zoneBelongedByExposure(item, zones)
	okHostname, zoneHostname := zoneForHostname(item.Hostname, zones)
	if okExposure != okHostname || zoneExposure != zoneHostname {
		t.Errorf("zoneBelongedByExposure() = %v %q, want the same zone as zoneForHostname(), %v %q", okExposure, zoneExposure, okHostname, zoneHostname)
	}
}

func Test_zoneForHostnameLongestSuffixWins(t *testing.T) {
	const hostname = "a.sub.example.com"

	// the case ListZones order used to decide: the parent zone is listed first
	// and also suffix matches, but Cloudflare answers the name from the child
	// zone, which is where the record lives
	parentFirst := []string{"example.com", "sub.example.com"}
	if ok, zone := zoneForHostname(hostname, parentFirst); !ok || zone != "sub.example.com" {
		t.Errorf("zoneForHostname() with the parent listed first = %v %q, want true sub.example.com", ok, zone)
	}

	// and the answer must not depend on the order at all. deep.sub.example.com
	// is a longer zone name that does not cover the hostname, so a match has to
	// stay a match, not merely the longest name in the list
	for _, zones := range [][]string{
		{"sub.example.com", "example.com"},
		{"example.com", "sub.example.com"},
		{"example.com", "deep.sub.example.com", "sub.example.com"},
		{"deep.sub.example.com", "sub.example.com", "example.com"},
	} {
		if ok, zone := zoneForHostname(hostname, zones); !ok || zone != "sub.example.com" {
			t.Errorf("zoneForHostname(%q, %v) = %v %q, want true sub.example.com", hostname, zones, ok, zone)
		}
	}

	// a hostname under the deeper zone resolves to the deeper zone, whichever
	// way round the three are listed
	if ok, zone := zoneForHostname("x.deep.sub.example.com", []string{"example.com", "sub.example.com", "deep.sub.example.com"}); !ok || zone != "deep.sub.example.com" {
		t.Errorf("zoneForHostname() = %v %q, want true deep.sub.example.com", ok, zone)
	}

	// one zone, and no zone, behave exactly as before
	if ok, zone := zoneForHostname(hostname, []string{"example.com"}); !ok || zone != "example.com" {
		t.Errorf("zoneForHostname() with a single zone = %v %q, want true example.com", ok, zone)
	}
	if ok, zone := zoneForHostname("app.elsewhere.com", parentFirst); ok || zone != "" {
		t.Errorf("zoneForHostname() = %v %q, want false \"\" for a hostname outside every zone", ok, zone)
	}
	if ok, zone := zoneForHostname(hostname, nil); ok || zone != "" {
		t.Errorf("zoneForHostname() with no zones = %v %q, want false \"\"", ok, zone)
	}
}

func Test_removedHostnamesInZone(t *testing.T) {
	const hostname = "withdrawn.example.com"
	cname := cloudflare.DNSRecord{ID: "rec-cname", Type: "CNAME", Name: hostname}
	txt := cloudflare.DNSRecord{ID: "rec-txt", Type: "TXT", Name: "_ctic_managed." + hostname}

	tests := []struct {
		name       string
		interested []string
		records    []cloudflare.DNSRecord
		deleted    []DNSOperationDelete
		want       map[string]struct{}
	}{
		{
			name:       "a hostname this pass deleted the record of is confirmed gone",
			interested: []string{hostname},
			records:    []cloudflare.DNSRecord{cname, txt},
			deleted:    []DNSOperationDelete{{OldRecord: cname}, {OldRecord: txt}},
			want:       map[string]struct{}{hostname: {}},
		},
		{
			name:       "a hostname the zone never held is confirmed gone",
			interested: []string{hostname},
			records:    []cloudflare.DNSRecord{{ID: "rec-other", Type: "CNAME", Name: "other.example.com"}},
			want:       map[string]struct{}{hostname: {}},
		},
		{
			// the relinquish path keeps a CNAME a third party repointed, and
			// reporting it gone would strip the Access application off a
			// hostname somebody else is now serving
			name:       "a surviving CNAME means the hostname still resolves",
			interested: []string{hostname},
			records:    []cloudflare.DNSRecord{cname},
			want:       map[string]struct{}{},
		},
		{
			// any record type, not only CNAME: an A record resolves just as well
			name:       "a hostname repointed to an A record still resolves",
			interested: []string{hostname},
			records:    []cloudflare.DNSRecord{{ID: "rec-a", Type: "A", Name: hostname}},
			want:       map[string]struct{}{},
		},
		{
			name:       "deleting the ownership TXT while the CNAME survives is not a removal",
			interested: []string{hostname},
			records:    []cloudflare.DNSRecord{cname, txt},
			deleted:    []DNSOperationDelete{{OldRecord: txt}},
			want:       map[string]struct{}{},
		},
		{
			name:       "the join is case insensitive, Cloudflare lowercases and Kubernetes does not",
			interested: []string{"Withdrawn.Example.COM"},
			records:    []cloudflare.DNSRecord{{ID: "rec-cname", Type: "CNAME", Name: hostname}},
			want:       map[string]struct{}{},
		},
		{
			name:    "no interested hostname reports nothing",
			records: []cloudflare.DNSRecord{cname},
			want:    map[string]struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := removedHostnamesInZone(tt.interested, tt.records, tt.deleted); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("removedHostnamesInZone() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_interestedHostnamesByZone(t *testing.T) {
	// a subdomain zone alongside its parent, both suffix match every hostname
	// under the child, and only one of them holds the records
	zones := []string{"sub.example.com", "example.com"}
	interested := map[string]struct{}{
		"a.sub.example.com": {},
		"b.sub.example.com": {},
		"c.example.com":     {},
		"app.elsewhere.com": {},
	}

	got := interestedHostnamesByZone(interested, zones)
	want := map[string][]string{
		// each hostname appears under exactly one zone, so no zone that never
		// held the record can report it gone
		"sub.example.com": {"a.sub.example.com", "b.sub.example.com"},
		"example.com":     {"c.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("interestedHostnamesByZone() = %v, want %v", got, want)
	}

	// nothing withdrawn means no zone is visited on account of the removal
	// signal at all
	if got := interestedHostnamesByZone(nil, zones); len(got) != 0 {
		t.Errorf("interestedHostnamesByZone() with nothing interested = %v, want empty", got)
	}
}
