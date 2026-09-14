package controller

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ingressWithAnnotations(annotations map[string]string) networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "default",
			Name:        "whatever",
			Annotations: annotations,
		},
	}
}

func Test_parseAccessSettings(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		annotations map[string]string
		want        *accessSettings
		wantErr     bool
	}{
		{
			name:        "no annotations produces no settings",
			host:        "test.example.com",
			annotations: map[string]string{},
			want:        nil,
		},
		{
			name: "access true alone enables access with no overrides",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess: AnnotationAccessTrue,
			},
			want: &accessSettings{Enabled: true},
		},
		{
			name: "access false is not enabled",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess: AnnotationAccessFalse,
			},
			want: &accessSettings{Enabled: false},
		},
		{
			name: "access with an invalid boolean value is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess: "yes",
			},
			wantErr: true,
		},
		{
			name: "access policies without access true is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccessPolicies: "policy-a",
			},
			wantErr: true,
		},
		{
			name: "access allowed idps without access true is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccessAllowedIdps: "idp-a",
			},
			wantErr: true,
		},
		{
			name: "access session duration without access true is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccessSessionDuration: "24h",
			},
			wantErr: true,
		},
		{
			name: "access policies alongside access false is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:         AnnotationAccessFalse,
				AnnotationAccessPolicies: "policy-a",
			},
			wantErr: true,
		},
		{
			name: "comma separated policies are split and trimmed",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:         AnnotationAccessTrue,
				AnnotationAccessPolicies: "a, b ,c",
			},
			want: &accessSettings{
				Enabled:  true,
				Policies: []string{"a", "b", "c"},
			},
		},
		{
			name: "comma separated allowed idps are split and trimmed",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:            AnnotationAccessTrue,
				AnnotationAccessAllowedIdps: "idp-a , idp-b",
			},
			want: &accessSettings{
				Enabled:     true,
				AllowedIdps: []string{"idp-a", "idp-b"},
			},
		},
		{
			name: "empty policies annotation is rejected rather than clearing the default",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:         AnnotationAccessTrue,
				AnnotationAccessPolicies: "",
			},
			wantErr: true,
		},
		{
			name: "policies with an empty element are rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:         AnnotationAccessTrue,
				AnnotationAccessPolicies: "a,,b",
			},
			wantErr: true,
		},
		{
			name: "empty allowed idps annotation is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:            AnnotationAccessTrue,
				AnnotationAccessAllowedIdps: "",
			},
			wantErr: true,
		},
		{
			name: "session duration in hours is accepted",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessSessionDuration: "24h",
			},
			want: &accessSettings{
				Enabled:         true,
				SessionDuration: ptr.To("24h"),
			},
		},
		{
			name: "session duration in minutes is accepted",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessSessionDuration: "90m",
			},
			want: &accessSettings{
				Enabled:         true,
				SessionDuration: ptr.To("90m"),
			},
		},
		{
			name: "session duration zero seconds is preserved verbatim",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessSessionDuration: "0s",
			},
			want: &accessSettings{
				Enabled:         true,
				SessionDuration: ptr.To("0s"),
			},
		},
		{
			// a Go duration, and the spelling Cloudflare's own API
			// documentation uses for session_duration
			name: "multi unit session duration is accepted",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessSessionDuration: "1h30m",
			},
			want: &accessSettings{
				Enabled:         true,
				SessionDuration: ptr.To("1h30m"),
			},
		},
		{
			name: "negative session duration is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessSessionDuration: "-1h",
			},
			wantErr: true,
		},
		{
			name: "unparseable session duration is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessSessionDuration: "banana",
			},
			wantErr: true,
		},
		{
			name: "empty session duration is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessSessionDuration: "",
			},
			wantErr: true,
		},
		{
			name: "access combined with disable dns management is rejected",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:               AnnotationAccessTrue,
				AnnotationDisableDNSManagement: AnnotationDisableDNSManagementTrue,
			},
			wantErr: true,
		},
		{
			name: "access alongside disable dns management false is accepted",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:               AnnotationAccessTrue,
				AnnotationDisableDNSManagement: AnnotationDisableDNSManagementFalse,
			},
			want: &accessSettings{Enabled: true},
		},
		{
			name: "access on a wildcard host is rejected",
			host: "*.example.com",
			annotations: map[string]string{
				AnnotationAccess: AnnotationAccessTrue,
			},
			wantErr: true,
		},
		{
			name: "no access annotation on a wildcard host is fine",
			host: "*.example.com",
			annotations: map[string]string{
				AnnotationDisableDNSManagement: AnnotationDisableDNSManagementTrue,
			},
			want: nil,
		},
		{
			name: "all four annotations resolve together",
			host: "test.example.com",
			annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessPolicies:        "policy-a,policy-b",
				AnnotationAccessAllowedIdps:     "idp-a",
				AnnotationAccessSessionDuration: "12h",
			},
			want: &accessSettings{
				Enabled:         true,
				Policies:        []string{"policy-a", "policy-b"},
				AllowedIdps:     []string{"idp-a"},
				SessionDuration: ptr.To("12h"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAccessSettings(ingressWithAnnotations(tt.annotations), tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAccessSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAccessSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromIngressToExposureAccessAnnotations(t *testing.T) {
	// the annotations are read at rule scope and splatted into every exposure
	// the rule produces, and the hostname is lowercased at the source so the
	// Cloudflare side of the join, which is always lowercase, matches
	pathType := networkingv1.PathTypePrefix
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "access-multi-path",
			Annotations: map[string]string{
				AnnotationAccess:                AnnotationAccessTrue,
				AnnotationAccessPolicies:        "policy-a,policy-b",
				AnnotationAccessAllowedIdps:     "idp-a",
				AnnotationAccessSessionDuration: "12h",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "Ops-Bot.Example.COM",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "my-app",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
								{
									Path:     "/api",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "my-app",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	service := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "my-app",
		},
		Spec: v1.ServiceSpec{
			ClusterIP: "10.0.0.1",
			Ports:     []v1.ServicePort{{Port: 80}},
		},
	}
	kubeClient := fake.NewClientBuilder().WithObjects(&service).Build()

	exposures, err := FromIngressToExposure(context.Background(), logr.Discard(), kubeClient, record.NewFakeRecorder(8), ingress, "cluster.local")
	if err != nil {
		t.Fatalf("FromIngressToExposure() unexpected error: %v", err)
	}
	if len(exposures) != 2 {
		t.Fatalf("expected one exposure per path, got %d", len(exposures))
	}
	for _, item := range exposures {
		if item.Hostname != "ops-bot.example.com" {
			t.Errorf("expected the hostname to be lowercased, got %s", item.Hostname)
		}
		if !item.AccessEnabled {
			t.Errorf("expected AccessEnabled on path %s", item.PathPrefix)
		}
		if !reflect.DeepEqual(item.AccessPolicies, []string{"policy-a", "policy-b"}) {
			t.Errorf("unexpected AccessPolicies on path %s: %v", item.PathPrefix, item.AccessPolicies)
		}
		if !reflect.DeepEqual(item.AccessAllowedIdps, []string{"idp-a"}) {
			t.Errorf("unexpected AccessAllowedIdps on path %s: %v", item.PathPrefix, item.AccessAllowedIdps)
		}
		if item.AccessSessionDuration == nil || *item.AccessSessionDuration != "12h" {
			t.Errorf("unexpected AccessSessionDuration on path %s: %v", item.PathPrefix, item.AccessSessionDuration)
		}
	}
}

func TestFromIngressToExposureAccessOnWildcardHostFails(t *testing.T) {
	pathType := networkingv1.PathTypePrefix
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "access-wildcard",
			Annotations: map[string]string{
				AnnotationAccess: AnnotationAccessTrue,
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "*.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "my-app",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	exposures, err := FromIngressToExposure(context.Background(), logr.Discard(), nil, record.NewFakeRecorder(8), ingress, "cluster.local")
	if err == nil {
		t.Fatalf("expected access on a wildcard host to be rejected, got %d exposures", len(exposures))
	}
	if len(exposures) != 0 {
		t.Fatalf("expected no exposures on a transform failure, got %d", len(exposures))
	}
}

func Test_parseCSVAnnotation(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        []string
		wantErr     bool
	}{
		{
			name:        "absent annotation produces nil",
			annotations: map[string]string{},
			want:        nil,
		},
		{
			name:        "single element",
			annotations: map[string]string{AnnotationAccessPolicies: "a"},
			want:        []string{"a"},
		},
		{
			name:        "elements are trimmed",
			annotations: map[string]string{AnnotationAccessPolicies: " a , b "},
			want:        []string{"a", "b"},
		},
		{
			name:        "present but empty is an error",
			annotations: map[string]string{AnnotationAccessPolicies: ""},
			wantErr:     true,
		},
		{
			name:        "whitespace only is an error",
			annotations: map[string]string{AnnotationAccessPolicies: "   "},
			wantErr:     true,
		},
		{
			name:        "empty element is an error",
			annotations: map[string]string{AnnotationAccessPolicies: "a,,b"},
			wantErr:     true,
		},
		{
			name:        "trailing comma is an error",
			annotations: map[string]string{AnnotationAccessPolicies: "a,b,"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCSVAnnotation(ingressWithAnnotations(tt.annotations), AnnotationAccessPolicies)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCSVAnnotation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCSVAnnotation() = %v, want %v", got, tt.want)
			}
		})
	}
}
