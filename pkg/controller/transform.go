package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/exposure"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
)

const (
	EventReasonTLSIgnored      = "TLSIgnored"
	EventReasonRuleSkipped     = "RuleSkipped"
	EventReasonTransformFailed = "TransformFailed"
	EventReasonSyncFailed      = "CloudflareSyncFailed"
	EventReasonSynced          = "CloudflareSynced"
	// EventReasonAccessNotEnabled is emitted on an ingress that requests
	// Cloudflare Access while the controller cannot provide it. The ingress is
	// not exposed at all, so the hostname goes dark rather than being published
	// without the protection its annotations asked for.
	EventReasonAccessNotEnabled = "AccessNotEnabled"
)

func FromIngressToExposure(ctx context.Context, logger logr.Logger, kubeClient client.Client, recorder record.EventRecorder, ingress networkingv1.Ingress, clusterDomain string) ([]exposure.Exposure, error) {
	isDeleted := ingress.DeletionTimestamp != nil

	if len(ingress.Spec.TLS) > 0 {
		logger.Info("ingress has tls specified, SSL Passthrough is not supported, it will be ignored.")
		recorder.Event(&ingress, v1.EventTypeWarning, EventReasonTLSIgnored, "ingress has tls specified, SSL Passthrough is not supported, it will be ignored")
	}

	var result []exposure.Exposure
	for _, rule := range ingress.Spec.Rules {
		if rule.Host == "" {
			return nil, errors.Errorf("host in ingress %s/%s is empty", ingress.GetNamespace(), ingress.GetName())
		}

		// rule.HTTP is optional in the Ingress API, a rule may carry only a
		// host, skip it and keep processing the remaining rules
		if rule.HTTP == nil {
			logger.Info("ingress rule has no http section, skipped",
				"ingress", fmt.Sprintf("%s/%s", ingress.GetNamespace(), ingress.GetName()),
				"host", rule.Host,
			)
			recorder.Eventf(&ingress, v1.EventTypeWarning, EventReasonRuleSkipped, "rule for host %s has no http section, skipped", rule.Host)
			continue
		}

		// Kubernetes does not normalise rule.Host while Cloudflare returns
		// hostnames lowercased, normalise once at the source so the DNS path and
		// the Access path join on the same key
		hostname := strings.ToLower(rule.Host)
		scheme := "http"

		if backendProtocol, ok := getAnnotation(ingress.Annotations, AnnotationBackendProtocol); ok {
			scheme = backendProtocol
		}

		var httpHostHeader *string

		if header, ok := getAnnotation(ingress.Annotations, AnnotationHTTPHostHeader); ok {
			httpHostHeader = ptr.To(header)
		}

		var originServerName *string

		if name, ok := getAnnotation(ingress.Annotations, AnnotationOriginServerName); ok {
			originServerName = ptr.To(name)
		}

		disableDNSManagement := false

		if value, ok := getAnnotation(ingress.Annotations, AnnotationDisableDNSManagement); ok {
			switch value {
			case AnnotationDisableDNSManagementTrue:
				disableDNSManagement = true
			case AnnotationDisableDNSManagementFalse:
				disableDNSManagement = false
			default:
				return nil, errors.Errorf(
					"invalid value for annotation %s, available values: \"%s\" or \"%s\"",
					AnnotationDisableDNSManagement,
					AnnotationDisableDNSManagementTrue,
					AnnotationDisableDNSManagementFalse,
				)
			}
		}

		originRequest, err := parseOriginRequestSettings(ingress.Annotations, scheme)
		if err != nil {
			return nil, err
		}

		access, err := parseAccessSettings(ingress, hostname)
		if err != nil {
			return nil, err
		}

		accessEnabled := access != nil && access.Enabled
		var accessPolicies, accessAllowedIdps []string
		var accessSessionDuration *string
		if accessEnabled {
			accessPolicies = access.Policies
			accessAllowedIdps = access.AllowedIdps
			accessSessionDuration = access.SessionDuration
		}

		var proxySSLVerifyEnabled *bool

		if proxySSLVerify, ok := getAnnotation(ingress.Annotations, AnnotationProxySSLVerify); ok {
			switch proxySSLVerify {
			case AnnotationProxySSLVerifyOn:
				proxySSLVerifyEnabled = ptr.To(true)
			case AnnotationProxySSLVerifyOff:
				proxySSLVerifyEnabled = ptr.To(false)
			default:
				return nil, errors.Errorf(
					"invalid value for annotation %s, available values: \"%s\" or \"%s\"",
					AnnotationProxySSLVerify,
					AnnotationProxySSLVerifyOn,
					AnnotationProxySSLVerifyOff,
				)
			}
		}

		for _, path := range rule.HTTP.Paths {
			namespacedName := types.NamespacedName{
				Namespace: ingress.GetNamespace(),
				Name:      path.Backend.Service.Name,
			}
			service := v1.Service{}
			err := kubeClient.Get(ctx, namespacedName, &service)
			if err != nil {
				return nil, errors.Wrapf(err, "fetch service %s", namespacedName)
			}

			host, err := getHostFromService(&service, clusterDomain)
			if err != nil {
				return nil, err
			}

			var port int32
			if path.Backend.Service.Port.Name != "" {
				ok, extractedPort := getPortWithName(service.Spec.Ports, path.Backend.Service.Port.Name)
				if !ok {
					return nil, errors.Errorf("service %s has no port named %s", namespacedName, path.Backend.Service.Port.Name)
				}
				port = extractedPort
			} else {
				port = path.Backend.Service.Port.Number
			}

			var supportedPathTypes = map[networkingv1.PathType]struct{}{
				networkingv1.PathTypePrefix:                 {},
				networkingv1.PathTypeImplementationSpecific: {},
			}

			if path.PathType == nil {
				return nil, errors.Errorf("path type in ingress %s/%s is nil", ingress.GetNamespace(), ingress.GetName())
			}

			if _, ok := supportedPathTypes[*path.PathType]; !ok {
				return nil, errors.Errorf("path type in ingress %s/%s is %s, which is not supported", ingress.GetNamespace(), ingress.GetName(), *path.PathType)
			}

			result = append(result, exposure.Exposure{
				Hostname:               hostname,
				ServiceTarget:          fmt.Sprintf("%s://%s:%d", scheme, host, port),
				PathPrefix:             path.Path,
				IsDeleted:              isDeleted,
				ProxySSLVerifyEnabled:  proxySSLVerifyEnabled,
				HTTPHostHeader:         httpHostHeader,
				OriginServerName:       originServerName,
				DisableDNSManagement:   disableDNSManagement,
				AccessEnabled:          accessEnabled,
				AccessPolicies:         accessPolicies,
				AccessAllowedIdps:      accessAllowedIdps,
				AccessSessionDuration:  accessSessionDuration,
				ConnectTimeout:         originRequest.ConnectTimeout,
				TLSTimeout:             originRequest.TLSTimeout,
				TCPKeepAlive:           originRequest.TCPKeepAlive,
				NoHappyEyeballs:        originRequest.NoHappyEyeballs,
				KeepAliveConnections:   originRequest.KeepAliveConnections,
				KeepAliveTimeout:       originRequest.KeepAliveTimeout,
				NoTLSVerify:            originRequest.NoTLSVerify,
				DisableChunkedEncoding: originRequest.DisableChunkedEncoding,
				HTTP2Origin:            originRequest.HTTP2Origin,
			})
		}
	}

	return result, nil
}

func getHostFromService(service *v1.Service, clusterDomain string) (string, error) {
	if service.Spec.ClusterIP == "None" {
		return "", errors.Errorf("service %s has None for cluster ip, headless service is not supported", client.ObjectKeyFromObject(service))
	}

	if service.Spec.Type == v1.ServiceTypeExternalName {
		if service.Spec.ExternalName != "" {
			return service.Spec.ExternalName, nil
		}
	}

	// Use FQDN service name instead of cluster IP for better stability
	// Format: <service-name>.<namespace>.svc.<cluster-domain>
	return fmt.Sprintf("%s.%s.svc.%s", service.Name, service.Namespace, clusterDomain), nil
}

func getPortWithName(ports []v1.ServicePort, portName string) (bool, int32) {
	for _, port := range ports {
		if port.Name == portName {
			return true, port.Port
		}
	}
	return false, 0
}

func getAnnotation(annotations map[string]string, key string) (string, bool) {
	value, ok := annotations[key]
	return value, ok
}

// originRequestSettings carries the parsed originRequest related annotations,
// they apply to every rule generated from the ingress.
type originRequestSettings struct {
	ConnectTimeout         *time.Duration
	TLSTimeout             *time.Duration
	TCPKeepAlive           *time.Duration
	NoHappyEyeballs        *bool
	KeepAliveConnections   *int
	KeepAliveTimeout       *time.Duration
	NoTLSVerify            *bool
	DisableChunkedEncoding *bool
	HTTP2Origin            *bool
}

func parseOriginRequestSettings(annotations map[string]string, scheme string) (originRequestSettings, error) {
	settings := originRequestSettings{}
	var err error

	if settings.ConnectTimeout, err = parseDurationAnnotation(annotations, AnnotationConnectTimeout); err != nil {
		return settings, err
	}
	if settings.TLSTimeout, err = parseDurationAnnotation(annotations, AnnotationTLSTimeout); err != nil {
		return settings, err
	}
	if settings.TCPKeepAlive, err = parseDurationAnnotation(annotations, AnnotationTCPKeepAlive); err != nil {
		return settings, err
	}
	if settings.NoHappyEyeballs, err = parseBoolAnnotation(annotations, AnnotationNoHappyEyeballs); err != nil {
		return settings, err
	}
	if settings.KeepAliveConnections, err = parseIntAnnotation(annotations, AnnotationKeepAliveConnections); err != nil {
		return settings, err
	}
	if settings.KeepAliveTimeout, err = parseDurationAnnotation(annotations, AnnotationKeepAliveTimeout); err != nil {
		return settings, err
	}
	if settings.NoTLSVerify, err = parseBoolAnnotation(annotations, AnnotationNoTLSVerify); err != nil {
		return settings, err
	}
	if settings.DisableChunkedEncoding, err = parseBoolAnnotation(annotations, AnnotationDisableChunkedEncoding); err != nil {
		return settings, err
	}
	if settings.HTTP2Origin, err = parseBoolAnnotation(annotations, AnnotationHTTP2Origin); err != nil {
		return settings, err
	}

	if settings.NoTLSVerify != nil {
		if _, ok := getAnnotation(annotations, AnnotationProxySSLVerify); ok {
			return settings, errors.Errorf(
				"annotations %s and %s are mutually exclusive, they express the same setting inverted",
				AnnotationNoTLSVerify, AnnotationProxySSLVerify,
			)
		}
	}

	// HTTP/2 to the origin needs TLS, cloudflared silently keeps HTTP/1.1 for
	// cleartext origins, reject the combination instead of not taking effect
	if settings.HTTP2Origin != nil && *settings.HTTP2Origin && scheme != "https" {
		return settings, errors.Errorf(
			"annotation %s requires %s: https, HTTP/2 to the origin only works over TLS",
			AnnotationHTTP2Origin, AnnotationBackendProtocol,
		)
	}

	return settings, nil
}

// accessSettings carries the parsed Cloudflare Access annotations, they apply
// to every rule generated from the ingress.
type accessSettings struct {
	Enabled         bool
	Policies        []string
	AllowedIdps     []string
	SessionDuration *string
}

// validAccessSessionDuration reports whether the value is an Access session
// duration this controller will forward.
//
// parseDurationAnnotation is deliberately not reused: it rejects non positive
// and sub second values, while "0s" - re authenticate on every request - is
// legitimate and security relevant here. The grammar is otherwise Go's, the
// same one the origin request annotations document, so multi unit spellings
// like "1h30m" - which is what Cloudflare's own API documentation uses - are
// accepted. Beyond being a non negative duration the value is passed through
// opaquely; Cloudflare is the authority on it.
func validAccessSessionDuration(value string) bool {
	duration, err := time.ParseDuration(value)
	return err == nil && duration >= 0
}

// parseAccessSettings parses the Cloudflare Access annotations at rule scope.
// It returns nil when the access annotation is absent, so an ingress without it
// keeps today's behaviour exactly. host is required because two of the
// validations are host dependent.
func parseAccessSettings(ingress networkingv1.Ingress, host string) (*accessSettings, error) {
	value, ok := getAnnotation(ingress.Annotations, AnnotationAccess)
	if !ok {
		// settings that would silently do nothing are a security surprise
		for _, key := range []string{AnnotationAccessPolicies, AnnotationAccessAllowedIdps, AnnotationAccessSessionDuration} {
			if _, present := getAnnotation(ingress.Annotations, key); present {
				return nil, errors.Errorf(
					"annotation %s requires %s: \"%s\"",
					key, AnnotationAccess, AnnotationAccessTrue,
				)
			}
		}
		return nil, nil
	}

	settings := accessSettings{}
	switch value {
	case AnnotationAccessTrue:
		settings.Enabled = true
	case AnnotationAccessFalse:
		settings.Enabled = false
	default:
		return nil, errors.Errorf(
			"invalid value for annotation %s, available values: \"%s\" or \"%s\"",
			AnnotationAccess,
			AnnotationAccessTrue,
			AnnotationAccessFalse,
		)
	}

	if !settings.Enabled {
		for _, key := range []string{AnnotationAccessPolicies, AnnotationAccessAllowedIdps, AnnotationAccessSessionDuration} {
			if _, present := getAnnotation(ingress.Annotations, key); present {
				return nil, errors.Errorf(
					"annotation %s requires %s: \"%s\"",
					key, AnnotationAccess, AnnotationAccessTrue,
				)
			}
		}
		return &settings, nil
	}

	// removing an Access application is gated on a positive "the DNS record is
	// gone" signal, and there is none for a record the controller does not own
	if dns, present := getAnnotation(ingress.Annotations, AnnotationDisableDNSManagement); present && dns == AnnotationDisableDNSManagementTrue {
		return nil, errors.Errorf(
			"annotation %s cannot be combined with %s: the controller cannot confirm the DNS record is gone before removing the Access application",
			AnnotationAccess, AnnotationDisableDNSManagement,
		)
	}

	// Cloudflare validates wildcard application domains differently and gates
	// them by plan, an application whose blast radius the operator did not
	// reason about must not be created silently
	if strings.HasPrefix(host, "*.") {
		return nil, errors.Errorf(
			"annotation %s is not supported on a wildcard host %s; create the Access application for the wildcard domain manually",
			AnnotationAccess, host,
		)
	}

	var err error
	if settings.Policies, err = parseCSVAnnotation(ingress, AnnotationAccessPolicies); err != nil {
		return nil, err
	}
	if settings.AllowedIdps, err = parseCSVAnnotation(ingress, AnnotationAccessAllowedIdps); err != nil {
		return nil, err
	}
	if duration, present := getAnnotation(ingress.Annotations, AnnotationAccessSessionDuration); present {
		if !validAccessSessionDuration(duration) {
			return nil, errors.Errorf(
				"invalid value %q for annotation %s, expect a non negative Go duration string like \"24h\", \"1h30m\" or \"0s\"",
				duration, AnnotationAccessSessionDuration,
			)
		}
		settings.SessionDuration = ptr.To(duration)
	}

	return &settings, nil
}

// parseCSVAnnotation splits a comma separated annotation into trimmed items.
// It returns nil when the annotation is absent, and an error when the
// annotation is present but empty or contains an empty element.
func parseCSVAnnotation(ingress networkingv1.Ingress, key string) ([]string, error) {
	value, ok := getAnnotation(ingress.Annotations, key)
	if !ok {
		return nil, nil
	}
	// present but empty is not "clear the controller default": an Access
	// application with no policies denies everyone, so a typo must not silently
	// produce a locked out hostname
	var items []string
	for _, item := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			return nil, errors.Errorf(
				"invalid value %q for annotation %s, expect a comma separated list with no empty elements",
				value, key,
			)
		}
		items = append(items, trimmed)
	}
	return items, nil
}

func parseBoolAnnotation(annotations map[string]string, key string) (*bool, error) {
	value, ok := getAnnotation(annotations, key)
	if !ok {
		return nil, nil
	}
	switch value {
	case "true":
		return ptr.To(true), nil
	case "false":
		return ptr.To(false), nil
	default:
		return nil, errors.Errorf("invalid value %q for annotation %s, available values: \"true\" or \"false\"", value, key)
	}
}

func parseDurationAnnotation(annotations map[string]string, key string) (*time.Duration, error) {
	value, ok := getAnnotation(annotations, key)
	if !ok {
		return nil, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return nil, errors.Errorf("invalid value %q for annotation %s, expect a Go duration string like \"30s\"", value, key)
	}
	// the Cloudflare API serializes originRequest durations in whole seconds
	if duration <= 0 || duration != duration.Truncate(time.Second) {
		return nil, errors.Errorf("invalid value %q for annotation %s, expect a positive duration in whole seconds", value, key)
	}
	return ptr.To(duration), nil
}

func parseIntAnnotation(annotations map[string]string, key string) (*int, error) {
	value, ok := getAnnotation(annotations, key)
	if !ok {
		return nil, nil
	}
	// zero is meaningful, for keepalive-connections it disables the idle
	// connection pool entirely
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return nil, errors.Errorf("invalid value %q for annotation %s, expect a non negative integer", value, key)
	}
	return ptr.To(parsed), nil
}
