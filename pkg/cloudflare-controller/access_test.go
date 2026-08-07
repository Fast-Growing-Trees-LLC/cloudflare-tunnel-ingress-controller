package cloudflarecontroller

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/exposure"
	"github.com/cloudflare/cloudflare-go"
	"github.com/go-logr/logr"
	"k8s.io/utils/ptr"
)

const WhateverTunnelName = "tunnel-in-test"
const WhateverOtherTunnelName = "other-tunnel-in-test"

// reusable Access policy IDs are UUIDs, and the planner quarantines a hostname
// whose policy list is not shaped like one, so the fixtures have to be too
const WhateverPolicyA = "8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b40"
const WhateverPolicyB = "8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b41"
const WhateverIdp = "idp-a"
const WhateverOtherIdp = "idp-b"
const WhateverHostname = "test.example.com"

// ownedTags renders the tag list of an application this controller owns, plus
// any tags an operator added by hand.
func ownedTags(extra ...string) []string {
	return append(ownershipTags(WhateverTunnelName), extra...)
}

// accessPolicies renders the read type Cloudflare returns, numbering the
// precedence in the order given.
func accessPolicies(ids ...string) []cloudflare.AccessPolicy {
	var policies []cloudflare.AccessPolicy
	for index, id := range ids {
		policies = append(policies, cloudflare.AccessPolicy{ID: id, Precedence: index + 1})
	}
	return policies
}

// accessEnabledExposure is one path of an ingress that asked for Access with
// no per ingress overrides.
func accessEnabledExposure(hostname string) exposure.Exposure {
	return exposure.Exposure{
		Hostname:      hostname,
		ServiceTarget: "http://10.0.0.1:233",
		PathPrefix:    "/",
		AccessEnabled: true,
	}
}

func Test_syncAccessApplications(t *testing.T) {
	type args struct {
		logger              logr.Logger
		exposures           []exposure.Exposure
		existedApplications []cloudflare.AccessApplication
		tunnelName          string
		tunnelId            string
		defaults            exposure.AccessDefaults
	}
	defaultDefaults := exposure.AccessDefaults{
		Enabled:  true,
		Policies: []string{WhateverPolicyA},
	}
	var tests = []struct {
		name            string
		args            args
		wantCreate      []AccessOperationCreate
		wantUpdate      []AccessOperationUpdate
		wantDelete      []AccessOperationDelete
		wantQuarantined map[string]string
		wantManaged     int
	}{
		{
			name: "no exposures produces no operations",
			args: args{
				logger:     logr.Discard(),
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "exposure without the access annotation produces no operations",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.1:233", PathPrefix: "/"},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "access enabled and no existing application creates one with ownership tags",
			args: args{
				logger:     logr.Discard(),
				exposures:  []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname: WhateverHostname,
					Name:     WhateverHostname,
					Policies: []string{WhateverPolicyA},
					Tags:     ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "created application carries the resolved policies in annotation order",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyB, WhateverPolicyA},
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname: WhateverHostname,
					Name:     WhateverHostname,
					Policies: []string{WhateverPolicyB, WhateverPolicyA},
					Tags:     ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "annotation policies override the controller default rather than merging",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyB},
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   exposure.AccessDefaults{Enabled: true, Policies: []string{WhateverPolicyA}},
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname: WhateverHostname,
					Name:     WhateverHostname,
					Policies: []string{WhateverPolicyB},
					Tags:     ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "controller default policies apply when the annotation is absent",
			args: args{
				logger:     logr.Discard(),
				exposures:  []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults: exposure.AccessDefaults{
					Enabled:     true,
					Policies:    []string{WhateverPolicyA, WhateverPolicyB},
					AllowedIdps: []string{WhateverIdp},
				},
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname:    WhateverHostname,
					Name:        WhateverHostname,
					Policies:    []string{WhateverPolicyA, WhateverPolicyB},
					AllowedIdps: []string{WhateverIdp},
					Tags:        ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "annotation session duration overrides the controller default",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:              WhateverHostname,
						ServiceTarget:         "http://10.0.0.1:233",
						PathPrefix:            "/",
						AccessEnabled:         true,
						AccessSessionDuration: ptr.To("24h"),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults: exposure.AccessDefaults{
					Enabled:         true,
					Policies:        []string{WhateverPolicyA},
					SessionDuration: "12h",
				},
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname:        WhateverHostname,
					Name:            WhateverHostname,
					SessionDuration: "24h",
					Policies:        []string{WhateverPolicyA},
					Tags:            ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "session duration 0s is preserved verbatim",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:              WhateverHostname,
						ServiceTarget:         "http://10.0.0.1:233",
						PathPrefix:            "/",
						AccessEnabled:         true,
						AccessSessionDuration: ptr.To("0s"),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults: exposure.AccessDefaults{
					Enabled:         true,
					Policies:        []string{WhateverPolicyA},
					SessionDuration: "12h",
				},
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname:        WhateverHostname,
					Name:            WhateverHostname,
					SessionDuration: "0s",
					Policies:        []string{WhateverPolicyA},
					Tags:            ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "empty controller session duration omits the field",
			args: args{
				logger:     logr.Discard(),
				exposures:  []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname:        WhateverHostname,
					Name:            WhateverHostname,
					SessionDuration: "",
					Policies:        []string{WhateverPolicyA},
					Tags:            ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "existing owned application matching desired state produces no operation",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "existing owned application with drifted policies is updated",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantUpdate: []AccessOperationUpdate{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownedTags(),
					},
					Spec: AccessApplicationSpec{
						Hostname: WhateverHostname,
						Name:     WhateverHostname,
						Policies: []string{WhateverPolicyA},
						Tags:     ownedTags(),
					},
				},
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "existing owned application with reordered policies is updated",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyB, WhateverPolicyA},
					},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA, WhateverPolicyB),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantUpdate: []AccessOperationUpdate{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA, WhateverPolicyB),
						Tags:     ownedTags(),
					},
					Spec: AccessApplicationSpec{
						Hostname: WhateverHostname,
						Name:     WhateverHostname,
						Policies: []string{WhateverPolicyB, WhateverPolicyA},
						Tags:     ownedTags(),
					},
				},
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "existing owned application whose policies are returned out of precedence order is not updated",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyA, WhateverPolicyB},
					},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:     "app-1",
						Name:   WhateverHostname,
						Domain: WhateverHostname,
						Type:   cloudflare.SelfHosted,
						// the API returned them in creation order, not
						// precedence order
						Policies: []cloudflare.AccessPolicy{
							{ID: WhateverPolicyB, Precedence: 2},
							{ID: WhateverPolicyA, Precedence: 1},
						},
						Tags: ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "existing owned application with reordered allowed idps is not updated",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:          WhateverHostname,
						ServiceTarget:     "http://10.0.0.1:233",
						PathPrefix:        "/",
						AccessEnabled:     true,
						AccessAllowedIdps: []string{WhateverIdp, WhateverOtherIdp},
					},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:          "app-1",
						Name:        WhateverHostname,
						Domain:      WhateverHostname,
						Type:        cloudflare.SelfHosted,
						AllowedIdps: []string{WhateverOtherIdp, WhateverIdp},
						Policies:    accessPolicies(WhateverPolicyA),
						Tags:        ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "existing owned application with drifted session duration is updated",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:              WhateverHostname,
						ServiceTarget:         "http://10.0.0.1:233",
						PathPrefix:            "/",
						AccessEnabled:         true,
						AccessSessionDuration: ptr.To("24h"),
					},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:              "app-1",
						Name:            WhateverHostname,
						Domain:          WhateverHostname,
						Type:            cloudflare.SelfHosted,
						SessionDuration: "12h",
						Policies:        accessPolicies(WhateverPolicyA),
						Tags:            ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantUpdate: []AccessOperationUpdate{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:              "app-1",
						Name:            WhateverHostname,
						Domain:          WhateverHostname,
						Type:            cloudflare.SelfHosted,
						SessionDuration: "12h",
						Policies:        accessPolicies(WhateverPolicyA),
						Tags:            ownedTags(),
					},
					Spec: AccessApplicationSpec{
						Hostname:        WhateverHostname,
						Name:            WhateverHostname,
						SessionDuration: "24h",
						Policies:        []string{WhateverPolicyA},
						Tags:            ownedTags(),
					},
				},
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "update preserves tags the controller did not add",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownedTags("team-infra", "billing-x"),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantUpdate: []AccessOperationUpdate{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownedTags("team-infra", "billing-x"),
					},
					Spec: AccessApplicationSpec{
						Hostname: WhateverHostname,
						Name:     WhateverHostname,
						Policies: []string{WhateverPolicyA},
						Tags:     ownedTags("team-infra", "billing-x"),
					},
				},
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "mixed case hostname matches its lowercased application domain and produces no operation",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure("Ops-Bot.Example.COM")},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     "ops-bot.example.com",
						Domain:   "ops-bot.example.com",
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "existing application without ownership tags is never updated",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "hand-made",
						Name:     "hand made application",
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     []string{"team-infra"},
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "existing application without ownership tags is never deleted",
			args: args{
				logger:    logr.Discard(),
				exposures: nil,
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:     "hand-made",
						Name:   "hand made application",
						Domain: WhateverHostname,
						Type:   cloudflare.SelfHosted,
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "existing application tagged for a different tunnel is never updated or deleted",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "other-tunnel-app",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownershipTags(WhateverOtherTunnelName),
					},
					{
						ID:       "other-tunnel-orphan",
						Name:     "gone.example.com",
						Domain:   "gone.example.com",
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownershipTags(WhateverOtherTunnelName),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "application carrying the legacy tunnel id form tag is recognised as owned and updated to the name form",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags: []string{
							ManagedAccessAppTag,
							fmt.Sprintf(ManagedAccessAppTunnelTagFormat, WhateverTunnelId),
						},
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantUpdate: []AccessOperationUpdate{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags: []string{
							ManagedAccessAppTag,
							fmt.Sprintf(ManagedAccessAppTunnelTagFormat, WhateverTunnelId),
						},
					},
					Spec: AccessApplicationSpec{
						Hostname: WhateverHostname,
						Name:     WhateverHostname,
						Policies: []string{WhateverPolicyA},
						Tags: []string{
							ManagedAccessAppTag,
							fmt.Sprintf(ManagedAccessAppTunnelTagFormat, WhateverTunnelId),
							fmt.Sprintf(ManagedAccessAppTunnelTagFormat, sanitiseTagName(WhateverTunnelName)),
						},
					},
				},
			},
			wantQuarantined: map[string]string{},
			wantManaged:     1,
		},
		{
			name: "owned application whose hostname is no longer exposed is deleted with reason withdrawn",
			args: args{
				logger:    logr.Discard(),
				exposures: nil,
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantDelete: []AccessOperationDelete{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
					Reason: AccessDeleteReasonWithdrawn,
				},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "owned application whose hostname is still exposed but opted out is deleted with reason opted-out",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.1:233", PathPrefix: "/"},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantDelete: []AccessOperationDelete{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
					Reason: AccessDeleteReasonOptedOut,
				},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "deleted exposure removes the owned application",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:      WhateverHostname,
						ServiceTarget: "http://10.0.0.1:233",
						PathPrefix:    "/",
						IsDeleted:     true,
						AccessEnabled: true,
					},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantDelete: []AccessOperationDelete{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
					Reason: AccessDeleteReasonWithdrawn,
				},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "multiple paths on one hostname produce exactly one create",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.1:233", PathPrefix: "/", AccessEnabled: true},
					{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.1:233", PathPrefix: "/api", AccessEnabled: true},
					{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.1:233", PathPrefix: "/ui", AccessEnabled: true},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname: WhateverHostname,
					Name:     WhateverHostname,
					Policies: []string{WhateverPolicyA},
					Tags:     ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "two exposures claiming one hostname, one enabled one not, produce one create",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.1:233", PathPrefix: "/"},
					{Hostname: WhateverHostname, ServiceTarget: "http://10.0.0.2:233", PathPrefix: "/api", AccessEnabled: true},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname: WhateverHostname,
					Name:     WhateverHostname,
					Policies: []string{WhateverPolicyA},
					Tags:     ownershipTags(WhateverTunnelName),
				}},
			},
			wantQuarantined: map[string]string{},
		},
		{
			name: "two enabled exposures claiming one hostname with conflicting settings quarantine it and produce no operations",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyA},
					},
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.2:233",
						PathPrefix:     "/api",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyB},
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{
				WhateverHostname: "two ingresses expose this hostname with conflicting Cloudflare Access settings; make them agree or expose the hostname from a single ingress",
			},
		},
		{
			name: "access enabled with no policies from either source quarantines the hostname and produces no operations",
			args: args{
				logger:     logr.Discard(),
				exposures:  []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   exposure.AccessDefaults{Enabled: true},
			},
			wantQuarantined: map[string]string{
				WhateverHostname: "access is enabled but no policies are configured; set the " +
					"cloudflare-tunnel-ingress-controller.strrl.dev/access-policies annotation or access.policies in the chart",
			},
		},
		{
			name: "a quarantined hostname with an existing owned application is not deleted",
			args: args{
				logger:    logr.Discard(),
				exposures: []exposure.Exposure{accessEnabledExposure(WhateverHostname)},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   exposure.AccessDefaults{Enabled: true},
			},
			wantQuarantined: map[string]string{
				WhateverHostname: "access is enabled but no policies are configured; set the " +
					"cloudflare-tunnel-ingress-controller.strrl.dev/access-policies annotation or access.policies in the chart",
			},
		},
		{
			// an id that reaches CreateAccessApplication and is rejected there
			// aborts PutExposures before the DNS step and stalls DNS for the
			// whole cluster, on every reconcile, until somebody edits the
			// annotation. Locally detectable, so it costs one hostname instead
			name: "access enabled with a policy id that is not a uuid quarantines the hostname and produces no operations",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyA, "Allow the ops team"},
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{
				WhateverHostname: "these Cloudflare Access policy IDs are not policy UUIDs: Allow the ops team" +
					"; the cloudflare-tunnel-ingress-controller.strrl.dev/access-policies annotation takes reusable policy IDs, not policy names",
			},
		},
		{
			// a quarantined hostname is not published, so whatever protects it
			// today has to survive, exactly as for the other quarantine causes
			name: "a hostname quarantined for a malformed policy id keeps its existing owned application",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					{
						Hostname:       WhateverHostname,
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{"not-a-uuid"},
					},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-1",
						Name:     WhateverHostname,
						Domain:   WhateverHostname,
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantQuarantined: map[string]string{
				WhateverHostname: "these Cloudflare Access policy IDs are not policy UUIDs: not-a-uuid" +
					"; the cloudflare-tunnel-ingress-controller.strrl.dev/access-policies annotation takes reusable policy IDs, not policy names",
			},
		},
		{
			name: "mixed plan: one create, one update, one delete, one unmanaged skip, one quarantine",
			args: args{
				logger: logr.Discard(),
				exposures: []exposure.Exposure{
					accessEnabledExposure("create.example.com"),
					accessEnabledExposure("update.example.com"),
					accessEnabledExposure("unmanaged.example.com"),
					{
						Hostname:       "quarantine.example.com",
						ServiceTarget:  "http://10.0.0.1:233",
						PathPrefix:     "/",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyA},
					},
					{
						Hostname:       "quarantine.example.com",
						ServiceTarget:  "http://10.0.0.2:233",
						PathPrefix:     "/api",
						AccessEnabled:  true,
						AccessPolicies: []string{WhateverPolicyB},
					},
				},
				existedApplications: []cloudflare.AccessApplication{
					{
						ID:       "app-update",
						Name:     "update.example.com",
						Domain:   "update.example.com",
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownedTags(),
					},
					{
						ID:       "app-delete",
						Name:     "delete.example.com",
						Domain:   "delete.example.com",
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
					{
						ID:       "app-unmanaged",
						Name:     "hand made",
						Domain:   "unmanaged.example.com",
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
					},
				},
				tunnelName: WhateverTunnelName,
				tunnelId:   WhateverTunnelId,
				defaults:   defaultDefaults,
			},
			wantCreate: []AccessOperationCreate{
				{Spec: AccessApplicationSpec{
					Hostname: "create.example.com",
					Name:     "create.example.com",
					Policies: []string{WhateverPolicyA},
					Tags:     ownershipTags(WhateverTunnelName),
				}},
			},
			wantUpdate: []AccessOperationUpdate{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-update",
						Name:     "update.example.com",
						Domain:   "update.example.com",
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyB),
						Tags:     ownedTags(),
					},
					Spec: AccessApplicationSpec{
						Hostname: "update.example.com",
						Name:     "update.example.com",
						Policies: []string{WhateverPolicyA},
						Tags:     ownedTags(),
					},
				},
			},
			wantDelete: []AccessOperationDelete{
				{
					OldApplication: cloudflare.AccessApplication{
						ID:       "app-delete",
						Name:     "delete.example.com",
						Domain:   "delete.example.com",
						Type:     cloudflare.SelfHosted,
						Policies: accessPolicies(WhateverPolicyA),
						Tags:     ownedTags(),
					},
					Reason: AccessDeleteReasonWithdrawn,
				},
			},
			wantQuarantined: map[string]string{
				"quarantine.example.com": "two ingresses expose this hostname with conflicting Cloudflare Access settings; make them agree or expose the hostname from a single ingress",
			},
			wantManaged: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCreate, gotUpdate, gotDelete, gotQuarantined, gotManaged, err := syncAccessApplications(
				tt.args.logger,
				tt.args.exposures,
				tt.args.existedApplications,
				tt.args.tunnelName,
				tt.args.tunnelId,
				tt.args.defaults,
			)
			if err != nil {
				t.Fatalf("syncAccessApplications() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(gotCreate, tt.wantCreate) {
				t.Errorf("syncAccessApplications() create = %v, want %v", gotCreate, tt.wantCreate)
			}
			if !reflect.DeepEqual(gotUpdate, tt.wantUpdate) {
				t.Errorf("syncAccessApplications() update = %v, want %v", gotUpdate, tt.wantUpdate)
			}
			if !reflect.DeepEqual(gotDelete, tt.wantDelete) {
				t.Errorf("syncAccessApplications() delete = %v, want %v", gotDelete, tt.wantDelete)
			}
			if !reflect.DeepEqual(gotQuarantined, tt.wantQuarantined) {
				t.Errorf("syncAccessApplications() quarantined = %v, want %v", gotQuarantined, tt.wantQuarantined)
			}
			if gotManaged != tt.wantManaged {
				t.Errorf("syncAccessApplications() managed = %v, want %v", gotManaged, tt.wantManaged)
			}
		})
	}
}

func Test_sanitiseTagName(t *testing.T) {
	tests := []struct {
		name       string
		tunnelName string
		want       string
	}{
		{
			name:       "already clean",
			tunnelName: "tunnel-in-test",
			want:       "tunnel-in-test-bef76a57",
		},
		{
			name:       "mixed case is lowered",
			tunnelName: "Tunnel-In-Test",
			want:       "tunnel-in-test-fd08a1bf",
		},
		{
			name:       "dots and underscores are replaced",
			tunnelName: "eks_sandbox.example",
			want:       "eks-sandbox-example-c8310ee2",
		},
		{
			name:       "over long names are truncated but stay distinct",
			tunnelName: "cloudflare-tunnel-ingress-controller-sandbox",
			want:       "cloudflare-tunnel-ingres-16887ecd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitiseTagName(tt.tunnelName); got != tt.want {
				t.Errorf("sanitiseTagName(%q) = %v, want %v", tt.tunnelName, got, tt.want)
			}
		})
	}

	// two names that truncate to the same 24 characters must not collide
	a := sanitiseTagName("cloudflare-tunnel-ingress-controller-sandbox")
	b := sanitiseTagName("cloudflare-tunnel-ingress-controller-prod")
	if a == b {
		t.Errorf("sanitiseTagName collided for two distinct tunnel names: %v", a)
	}

	// the sanitisation is not case sensitive but the hash is, so a rename that
	// only changes case still produces a distinct tag
	if sanitiseTagName("tunnel-in-test") == sanitiseTagName("Tunnel-In-Test") {
		t.Errorf("sanitiseTagName ignored a case only rename")
	}
}

func Test_ownershipTags(t *testing.T) {
	got := ownershipTags(WhateverTunnelName)
	want := []string{"ctic-managed", "ctic-tunnel-tunnel-in-test-bef76a57"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ownershipTags() = %v, want %v", got, want)
	}
}

func Test_hasOwnershipTags(t *testing.T) {
	nameFormTag := fmt.Sprintf(ManagedAccessAppTunnelTagFormat, sanitiseTagName(WhateverTunnelName))
	idFormTag := fmt.Sprintf(ManagedAccessAppTunnelTagFormat, WhateverTunnelId)

	tests := []struct {
		name string
		tags []string
		want bool
	}{
		{name: "nil tags", tags: nil, want: false},
		{name: "no tags at all", tags: []string{}, want: false},
		{name: "missing managed tag", tags: []string{nameFormTag}, want: false},
		{name: "missing tunnel tag", tags: []string{ManagedAccessAppTag}, want: false},
		{name: "name form", tags: []string{ManagedAccessAppTag, nameFormTag}, want: true},
		{name: "legacy id form", tags: []string{ManagedAccessAppTag, idFormTag}, want: true},
		{name: "both forms alongside user tags", tags: []string{"team-infra", ManagedAccessAppTag, idFormTag, nameFormTag}, want: true},
		{name: "another tunnel", tags: ownershipTags(WhateverOtherTunnelName), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := cloudflare.AccessApplication{Tags: tt.tags}
			if got := hasOwnershipTags(app, WhateverTunnelName, WhateverTunnelId); got != tt.want {
				t.Errorf("hasOwnershipTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_policyIDs(t *testing.T) {
	tests := []struct {
		name     string
		policies []cloudflare.AccessPolicy
		want     []string
	}{
		{name: "nil produces nil", policies: nil, want: nil},
		{
			name:     "already ordered",
			policies: []cloudflare.AccessPolicy{{ID: "a", Precedence: 1}, {ID: "b", Precedence: 2}},
			want:     []string{"a", "b"},
		},
		{
			name:     "sorted by precedence",
			policies: []cloudflare.AccessPolicy{{ID: "b", Precedence: 2}, {ID: "a", Precedence: 1}},
			want:     []string{"a", "b"},
		},
		{
			name:     "ties are broken on id",
			policies: []cloudflare.AccessPolicy{{ID: "b", Precedence: 0}, {ID: "a", Precedence: 0}},
			want:     []string{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyIDs(tt.policies); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("policyIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mergeTags(t *testing.T) {
	tests := []struct {
		name      string
		actual    []string
		ownership []string
		want      []string
	}{
		{
			name:      "no existing tags",
			actual:    nil,
			ownership: []string{"ctic-managed", "ctic-tunnel-x"},
			want:      []string{"ctic-managed", "ctic-tunnel-x"},
		},
		{
			name:      "operator tags are preserved in order",
			actual:    []string{"team-infra", "billing-x"},
			ownership: []string{"ctic-managed", "ctic-tunnel-x"},
			want:      []string{"team-infra", "billing-x", "ctic-managed", "ctic-tunnel-x"},
		},
		{
			name:      "ownership tags already present are not duplicated",
			actual:    []string{"ctic-managed", "ctic-tunnel-x", "team-infra"},
			ownership: []string{"ctic-managed", "ctic-tunnel-x"},
			want:      []string{"ctic-managed", "ctic-tunnel-x", "team-infra"},
		},
		{
			name:      "duplicates in the existing tags are collapsed",
			actual:    []string{"team-infra", "team-infra"},
			ownership: []string{"ctic-managed"},
			want:      []string{"team-infra", "ctic-managed"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeTags(tt.actual, tt.ownership)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeTags() = %v, want %v", got, tt.want)
			}
		})
	}

	// merging must not write through to the application's own tag slice
	actual := []string{"team-infra"}
	mergeTags(actual, []string{"ctic-managed"})
	if !reflect.DeepEqual(actual, []string{"team-infra"}) {
		t.Errorf("mergeTags() mutated its input: %v", actual)
	}
}

func Test_resolveAccessSettings(t *testing.T) {
	defaults := exposure.AccessDefaults{
		Enabled:         true,
		Policies:        []string{WhateverPolicyA},
		AllowedIdps:     []string{WhateverIdp},
		SessionDuration: "12h",
	}

	tests := []struct {
		name     string
		exposure exposure.Exposure
		defaults exposure.AccessDefaults
		want     AccessApplicationSpec
	}{
		{
			name:     "no annotations falls back to every controller default",
			exposure: accessEnabledExposure(WhateverHostname),
			defaults: defaults,
			want: AccessApplicationSpec{
				Hostname:        WhateverHostname,
				Name:            WhateverHostname,
				SessionDuration: "12h",
				Policies:        []string{WhateverPolicyA},
				AllowedIdps:     []string{WhateverIdp},
			},
		},
		{
			name: "every annotation overrides its default",
			exposure: exposure.Exposure{
				Hostname:              WhateverHostname,
				AccessEnabled:         true,
				AccessPolicies:        []string{WhateverPolicyB},
				AccessAllowedIdps:     []string{WhateverOtherIdp},
				AccessSessionDuration: ptr.To("0s"),
			},
			defaults: defaults,
			want: AccessApplicationSpec{
				Hostname:        WhateverHostname,
				Name:            WhateverHostname,
				SessionDuration: "0s",
				Policies:        []string{WhateverPolicyB},
				AllowedIdps:     []string{WhateverOtherIdp},
			},
		},
		{
			name:     "empty controller defaults leave every field zero",
			exposure: accessEnabledExposure(WhateverHostname),
			defaults: exposure.AccessDefaults{Enabled: true},
			want: AccessApplicationSpec{
				Hostname: WhateverHostname,
				Name:     WhateverHostname,
			},
		},
		{
			name:     "the hostname is lowercased and is also the application name",
			exposure: accessEnabledExposure("Ops-Bot.Example.COM"),
			defaults: exposure.AccessDefaults{Enabled: true, Policies: []string{WhateverPolicyA}},
			want: AccessApplicationSpec{
				Hostname: "ops-bot.example.com",
				Name:     "ops-bot.example.com",
				Policies: []string{WhateverPolicyA},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAccessSettings(tt.exposure, tt.defaults)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("resolveAccessSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_accessAppNeedsUpdate(t *testing.T) {
	base := cloudflare.AccessApplication{
		ID:              "app-1",
		Name:            WhateverHostname,
		Domain:          WhateverHostname,
		Type:            cloudflare.SelfHosted,
		SessionDuration: "12h",
		AllowedIdps:     []string{WhateverIdp},
		Policies:        accessPolicies(WhateverPolicyA, WhateverPolicyB),
		Tags:            ownedTags(),
	}
	baseSpec := AccessApplicationSpec{
		Hostname:        WhateverHostname,
		Name:            WhateverHostname,
		SessionDuration: "12h",
		AllowedIdps:     []string{WhateverIdp},
		Policies:        []string{WhateverPolicyA, WhateverPolicyB},
		Tags:            ownedTags(),
	}

	tests := []struct {
		name    string
		actual  func(cloudflare.AccessApplication) cloudflare.AccessApplication
		desired func(AccessApplicationSpec) AccessApplicationSpec
		want    bool
	}{
		{
			name: "identical is a no-op",
			want: false,
		},
		{
			name: "drifted name",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.Name = "something-else"
				return a
			},
			want: true,
		},
		{
			name: "domain differing only in case is not drift",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.Domain = "Test.Example.COM"
				return a
			},
			want: false,
		},
		{
			name: "wrong application type",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.Type = cloudflare.Bookmark
				return a
			},
			want: true,
		},
		{
			name: "drifted session duration",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.SessionDuration = "24h"
				return a
			},
			want: true,
		},
		{
			name: "an empty desired session duration cannot clear a set one",
			desired: func(s AccessApplicationSpec) AccessApplicationSpec {
				s.SessionDuration = ""
				return s
			},
			want: false,
		},
		{
			name: "drifted allowed idps",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.AllowedIdps = []string{WhateverOtherIdp}
				return a
			},
			want: true,
		},
		{
			name: "reordered allowed idps is not drift",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.AllowedIdps = []string{WhateverIdp}
				return a
			},
			desired: func(s AccessApplicationSpec) AccessApplicationSpec {
				s.AllowedIdps = []string{WhateverIdp}
				return s
			},
			want: false,
		},
		{
			name: "empty desired allowed idps cannot clear a set list",
			desired: func(s AccessApplicationSpec) AccessApplicationSpec {
				s.AllowedIdps = nil
				return s
			},
			want: false,
		},
		{
			name: "drifted policies",
			desired: func(s AccessApplicationSpec) AccessApplicationSpec {
				s.Policies = []string{WhateverPolicyA}
				return s
			},
			want: true,
		},
		{
			name: "reordered policies is drift, order is precedence",
			desired: func(s AccessApplicationSpec) AccessApplicationSpec {
				s.Policies = []string{WhateverPolicyB, WhateverPolicyA}
				return s
			},
			want: true,
		},
		{
			name: "missing ownership tag",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.Tags = []string{ManagedAccessAppTag}
				return a
			},
			want: true,
		},
		{
			name: "reordered tags is not drift",
			actual: func(a cloudflare.AccessApplication) cloudflare.AccessApplication {
				a.Tags = []string{ownedTags()[1], ownedTags()[0]}
				return a
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := base
			if tt.actual != nil {
				actual = tt.actual(base)
			}
			desired := baseSpec
			if tt.desired != nil {
				desired = tt.desired(baseSpec)
			}
			if got := accessAppNeedsUpdate(actual, desired); got != tt.want {
				t.Errorf("accessAppNeedsUpdate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_accessCreateParams(t *testing.T) {
	spec := AccessApplicationSpec{
		Hostname:        WhateverHostname,
		Name:            WhateverHostname,
		SessionDuration: "12h",
		Policies:        []string{WhateverPolicyA, WhateverPolicyB},
		AllowedIdps:     []string{WhateverIdp},
		Tags:            ownedTags(),
	}
	got := accessCreateParams(spec)
	want := cloudflare.CreateAccessApplicationParams{
		Name:            WhateverHostname,
		Domain:          WhateverHostname,
		Type:            cloudflare.SelfHosted,
		SessionDuration: "12h",
		AllowedIdps:     []string{WhateverIdp},
		Policies:        []string{WhateverPolicyA, WhateverPolicyB},
		Tags:            ownedTags(),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("accessCreateParams() = %+v, want %+v", got, want)
	}
}

func Test_accessUpdateParams(t *testing.T) {
	operation := AccessOperationUpdate{
		OldApplication: cloudflare.AccessApplication{ID: "app-1"},
		Spec: AccessApplicationSpec{
			Hostname:        WhateverHostname,
			Name:            WhateverHostname,
			SessionDuration: "12h",
			Policies:        []string{WhateverPolicyA, WhateverPolicyB},
			AllowedIdps:     []string{WhateverIdp},
			Tags:            ownedTags(),
		},
	}
	got := accessUpdateParams(operation)

	if got.ID != "app-1" {
		t.Errorf("accessUpdateParams() ID = %v, want app-1", got.ID)
	}
	// UpdateAccessApplicationParams.Policies is a *[]string documented as "if
	// this field is not provided, the existing policies will not be modified",
	// so a nil pointer silently fails to reconcile policy drift
	if got.Policies == nil {
		t.Fatalf("accessUpdateParams() must set Policies as a non nil pointer, policy drift would never be reconciled")
	}
	if !reflect.DeepEqual(*got.Policies, []string{WhateverPolicyA, WhateverPolicyB}) {
		t.Errorf("accessUpdateParams() Policies = %v, want %v", *got.Policies, []string{WhateverPolicyA, WhateverPolicyB})
	}
	if got.Domain != WhateverHostname || got.Name != WhateverHostname || got.Type != cloudflare.SelfHosted {
		t.Errorf("accessUpdateParams() = %+v, want the self hosted application for %s", got, WhateverHostname)
	}
	if !reflect.DeepEqual(got.Tags, ownedTags()) {
		t.Errorf("accessUpdateParams() Tags = %v, want %v", got.Tags, ownedTags())
	}
	if got.SessionDuration != "12h" {
		t.Errorf("accessUpdateParams() SessionDuration = %v, want 12h", got.SessionDuration)
	}
	if !reflect.DeepEqual(got.AllowedIdps, []string{WhateverIdp}) {
		t.Errorf("accessUpdateParams() AllowedIdps = %v, want %v", got.AllowedIdps, []string{WhateverIdp})
	}
}

func Test_malformedPolicyIDs(t *testing.T) {
	tests := []struct {
		name     string
		policies []string
		want     []string
	}{
		{
			name:     "reusable policy uuids are accepted",
			policies: []string{WhateverPolicyA, WhateverPolicyB},
		},
		{
			name:     "uppercase hex is still a uuid",
			policies: []string{"8B1C0D7E-4F2A-4B6C-9D31-0A5E7C2F1B40"},
		},
		{
			name:     "a policy name is not an id",
			policies: []string{"Allow the ops team"},
			want:     []string{"Allow the ops team"},
		},
		{
			name:     "malformed ids are reported in configuration order, valid ones are not",
			policies: []string{"policy-a", WhateverPolicyA, "8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b4"},
			want:     []string{"policy-a", "8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b4"},
		},
		{
			name:     "no policies at all is not a shape problem",
			policies: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := malformedPolicyIDs(tt.policies); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("malformedPolicyIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_sawOwnedApplications(t *testing.T) {
	owned := cloudflare.AccessApplication{ID: "app-1", Domain: WhateverHostname, Tags: ownedTags()}
	foreign := cloudflare.AccessApplication{ID: "app-2", Domain: "other.example.com", Tags: []string{ManagedAccessAppTag, "ctic-tunnel-" + sanitiseTagName(WhateverOtherTunnelName)}}

	tests := []struct {
		name         string
		applications []cloudflare.AccessApplication
		creates      []AccessOperationCreate
		want         bool
	}{
		{
			name: "nothing listed and nothing created owns nothing",
		},
		{
			name:         "an owned application in the listing counts",
			applications: []cloudflare.AccessApplication{owned},
			want:         true,
		},
		{
			// the latch is read by the NEXT reconcile, by which time this
			// create exists and is owned. Answering false here means a
			// following reconcile with nothing annotated skips the listing
			// and never reaps the application the operator just opted out of
			name:    "an application created in this pass counts, the listing that preceded it was empty",
			creates: []AccessOperationCreate{{Spec: AccessApplicationSpec{Hostname: WhateverHostname}}},
			want:    true,
		},
		{
			name:         "another tunnel's application is not ours",
			applications: []cloudflare.AccessApplication{foreign},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sawOwnedApplications(tt.applications, tt.creates, WhateverTunnelName, WhateverTunnelId); got != tt.want {
				t.Errorf("sawOwnedApplications() = %v, want %v", got, tt.want)
			}
		})
	}
}
