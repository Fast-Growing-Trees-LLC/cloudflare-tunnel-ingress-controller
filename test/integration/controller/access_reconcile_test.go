package controller

import (
	"context"
	"log"
	"os"
	"time"

	cloudflarecontroller "github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/cloudflare-controller"
	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/controller"
	"github.com/STRRL/cloudflare-tunnel-ingress-controller/pkg/exposure"
	"github.com/STRRL/cloudflare-tunnel-ingress-controller/test/fixtures"
	"github.com/go-logr/stdr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const AccessIntegrationTestNamespace = "cf-tunnel-access-test"
const testControllerClassName = "strrl.dev/cloudflare-tunnel-ingress-controller"

var _ cloudflarecontroller.TunnelClientInterface = &recordingTunnelClient{}

// recordingTunnelClient captures what the reconcile loop decided to publish, so
// a spec can assert that a hostname was withheld rather than exposed.
type recordingTunnelClient struct {
	called    bool
	exposures []exposure.Exposure
}

func (r *recordingTunnelClient) PutExposures(ctx context.Context, exposures []exposure.Exposure) error {
	r.called = true
	r.exposures = exposures
	return nil
}

func (r *recordingTunnelClient) TunnelDomain() string {
	return "recording.tunnel.com"
}

func (r *recordingTunnelClient) FetchTunnelToken(ctx context.Context) (string, error) {
	return "recording-token", nil
}

// drainEvents empties the fake recorder without blocking.
func drainEvents(recorder *record.FakeRecorder) []string {
	var events []string
	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			return events
		}
	}
}

var _ = Describe("reconcile ingresses requesting cloudflare access", func() {
	logger := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})

	// envtest runs no namespace controller, so an ingress created by an earlier
	// spec is never actually collected and stays visible to
	// listControlledIngresses. Scoping each spec to its own ingress class is what
	// keeps the specs independent.
	ingressClassNameFor := func(ns string) string {
		return "cloudflare-tunnel-" + ns
	}

	// cluster IPs are pinned, as in the transform specs: the envtest service CIDR
	// is small and letting the allocator choose here would race the hardcoded
	// addresses those specs expect, depending on the spec order Ginkgo picks
	prepareServiceAndIngress := func(ns string, clusterIP string, host string, annotations map[string]string) *networkingv1.Ingress {
		By("preparing service")
		service := v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:    ns,
				GenerateName: "test-service-",
			},
			Spec: v1.ServiceSpec{
				ClusterIP: clusterIP,
				Ports: []v1.ServicePort{
					{
						Name:     "http",
						Protocol: v1.ProtocolTCP,
						Port:     2333,
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: 8080,
						},
					},
				},
			},
		}
		err := kubeClient.Create(ctx, &service)
		Expect(err).ShouldNot(HaveOccurred())

		By("preparing ingress")
		allAnnotations := map[string]string{
			controller.WellKnownIngressAnnotation: ingressClassNameFor(ns),
		}
		for key, value := range annotations {
			allAnnotations[key] = value
		}
		ingress := networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:    ns,
				GenerateName: "test-ingress-",
				Annotations:  allAnnotations,
				// steady state: the finalizer is attached by the first reconcile.
				// Starting from there keeps attachFinalizer a no-op, so the status
				// update at the end of Reconcile does not conflict with the
				// resourceVersion the same call just bumped.
				Finalizers: []string{controller.IngressControllerFinalizer},
			},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{
					{
						Host: host,
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{
										Path:     "/",
										PathType: &pathTypePrefix,
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: service.Name,
												Port: networkingv1.ServiceBackendPort{
													Number: 2333,
												},
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
		err = kubeClient.Create(ctx, &ingress)
		Expect(err).ShouldNot(HaveOccurred())
		return &ingress
	}

	newController := func(ns string, recorder record.EventRecorder, tunnelClient cloudflarecontroller.TunnelClientInterface, access exposure.AccessDefaults) *controller.IngressController {
		return controller.NewIngressController(logger, kubeClient, recorder, ingressClassNameFor(ns), testControllerClassName, testClusterDomain, tunnelClient, access)
	}

	requestFor := func(ingress *networkingv1.Ingress) reconcile.Request {
		return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ingress.Namespace, Name: ingress.Name}}
	}

	It("should not expose an ingress carrying access-policies without the access annotation", func() {
		By("preparing namespace")
		namespaceFixtures := fixtures.NewKubernetesNamespaceFixtures(AccessIntegrationTestNamespace, kubeClient)
		ns, err := namespaceFixtures.Start(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		defer func() {
			By("cleaning up namespace")
			err := namespaceFixtures.Stop(ctx)
			Expect(err).ShouldNot(HaveOccurred())
		}()

		ingress := prepareServiceAndIngress(ns, "10.0.0.40", "orphan-policies.example.com", map[string]string{
			controller.AnnotationAccessPolicies: "policy-a",
		})

		By("reconciling the ingress")
		recorder := record.NewFakeRecorder(100)
		tunnelClient := &recordingTunnelClient{}
		_, err = newController(ns, recorder, tunnelClient, exposure.AccessDefaults{Enabled: true}).Reconcile(ctx, requestFor(ingress))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(tunnelClient.called).Should(BeTrue())
		Expect(tunnelClient.exposures).Should(BeEmpty())
		Expect(drainEvents(recorder)).Should(ContainElement(ContainSubstring("Warning " + controller.EventReasonTransformFailed)))
	})

	It("should not expose an ingress combining access with disable-dns-management", func() {
		By("preparing namespace")
		namespaceFixtures := fixtures.NewKubernetesNamespaceFixtures(AccessIntegrationTestNamespace, kubeClient)
		ns, err := namespaceFixtures.Start(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		defer func() {
			By("cleaning up namespace")
			err := namespaceFixtures.Stop(ctx)
			Expect(err).ShouldNot(HaveOccurred())
		}()

		ingress := prepareServiceAndIngress(ns, "10.0.0.41", "external-dns.example.com", map[string]string{
			controller.AnnotationAccess:               controller.AnnotationAccessTrue,
			controller.AnnotationDisableDNSManagement: controller.AnnotationDisableDNSManagementTrue,
		})

		By("reconciling the ingress")
		recorder := record.NewFakeRecorder(100)
		tunnelClient := &recordingTunnelClient{}
		_, err = newController(ns, recorder, tunnelClient, exposure.AccessDefaults{Enabled: true}).Reconcile(ctx, requestFor(ingress))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(tunnelClient.called).Should(BeTrue())
		Expect(tunnelClient.exposures).Should(BeEmpty())
		Expect(drainEvents(recorder)).Should(ContainElement(ContainSubstring("Warning " + controller.EventReasonTransformFailed)))
	})

	It("should not expose an ingress requesting access on a wildcard host", func() {
		By("preparing namespace")
		namespaceFixtures := fixtures.NewKubernetesNamespaceFixtures(AccessIntegrationTestNamespace, kubeClient)
		ns, err := namespaceFixtures.Start(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		defer func() {
			By("cleaning up namespace")
			err := namespaceFixtures.Stop(ctx)
			Expect(err).ShouldNot(HaveOccurred())
		}()

		ingress := prepareServiceAndIngress(ns, "10.0.0.42", "*.example.com", map[string]string{
			controller.AnnotationAccess: controller.AnnotationAccessTrue,
		})

		By("reconciling the ingress")
		recorder := record.NewFakeRecorder(100)
		tunnelClient := &recordingTunnelClient{}
		_, err = newController(ns, recorder, tunnelClient, exposure.AccessDefaults{Enabled: true}).Reconcile(ctx, requestFor(ingress))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(tunnelClient.called).Should(BeTrue())
		Expect(tunnelClient.exposures).Should(BeEmpty())
		Expect(drainEvents(recorder)).Should(ContainElement(ContainSubstring("Warning " + controller.EventReasonTransformFailed)))
	})

	It("should not expose an ingress requesting access when the controller has access disabled", func() {
		By("preparing namespace")
		namespaceFixtures := fixtures.NewKubernetesNamespaceFixtures(AccessIntegrationTestNamespace, kubeClient)
		ns, err := namespaceFixtures.Start(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		defer func() {
			By("cleaning up namespace")
			err := namespaceFixtures.Stop(ctx)
			Expect(err).ShouldNot(HaveOccurred())
		}()

		ingress := prepareServiceAndIngress(ns, "10.0.0.43", "guarded.example.com", map[string]string{
			controller.AnnotationAccess:         controller.AnnotationAccessTrue,
			controller.AnnotationAccessPolicies: "policy-a",
		})

		By("reconciling the ingress on a controller started without --access-enabled")
		recorder := record.NewFakeRecorder(100)
		tunnelClient := &recordingTunnelClient{}
		_, err = newController(ns, recorder, tunnelClient, exposure.AccessDefaults{Enabled: false}).Reconcile(ctx, requestFor(ingress))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(tunnelClient.called).Should(BeTrue())
		// fail closed, the hostname goes dark rather than being published without
		// the protection its annotations asked for
		Expect(tunnelClient.exposures).Should(BeEmpty())
		events := drainEvents(recorder)
		Expect(events).Should(ContainElement(ContainSubstring("Warning " + controller.EventReasonAccessNotEnabled)))
		Expect(events).ShouldNot(ContainElement(ContainSubstring(controller.EventReasonTransformFailed)))
	})

	It("should expose an ingress requesting access when the controller has access enabled", func() {
		By("preparing namespace")
		namespaceFixtures := fixtures.NewKubernetesNamespaceFixtures(AccessIntegrationTestNamespace, kubeClient)
		ns, err := namespaceFixtures.Start(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		defer func() {
			By("cleaning up namespace")
			err := namespaceFixtures.Stop(ctx)
			Expect(err).ShouldNot(HaveOccurred())
		}()

		ingress := prepareServiceAndIngress(ns, "10.0.0.45", "protected.example.com", map[string]string{
			controller.AnnotationAccess:                controller.AnnotationAccessTrue,
			controller.AnnotationAccessPolicies:        "8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b40",
			controller.AnnotationAccessSessionDuration: "12h",
		})

		By("reconciling the ingress on a controller started with --access-enabled")
		recorder := record.NewFakeRecorder(100)
		tunnelClient := &recordingTunnelClient{}
		_, err = newController(ns, recorder, tunnelClient, exposure.AccessDefaults{Enabled: true}).Reconcile(ctx, requestFor(ingress))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(tunnelClient.called).Should(BeTrue())
		// the counterpart of the fail closed spec above: with the controller
		// able to do Access the ingress must actually reach the tunnel client,
		// carrying what it asked for. Without this assertion the guard could
		// drop every Access annotated ingress and the whole suite would stay
		// green while the feature is dead end to end
		Expect(tunnelClient.exposures).Should(HaveLen(1))
		for _, item := range tunnelClient.exposures {
			Expect(item.Hostname).Should(Equal("protected.example.com"))
			Expect(item.AccessEnabled).Should(BeTrue())
			Expect(item.AccessPolicies).Should(Equal([]string{"8b1c0d7e-4f2a-4b6c-9d31-0a5e7c2f1b40"}))
			Expect(item.AccessSessionDuration).ShouldNot(BeNil())
			Expect(*item.AccessSessionDuration).Should(Equal("12h"))
		}
		events := drainEvents(recorder)
		Expect(events).ShouldNot(ContainElement(ContainSubstring(controller.EventReasonAccessNotEnabled)))
		Expect(events).ShouldNot(ContainElement(ContainSubstring(controller.EventReasonTransformFailed)))
	})

	It("should requeue on the access resync interval only while access is enabled", func() {
		By("preparing namespace")
		namespaceFixtures := fixtures.NewKubernetesNamespaceFixtures(AccessIntegrationTestNamespace, kubeClient)
		ns, err := namespaceFixtures.Start(ctx)
		Expect(err).ShouldNot(HaveOccurred())

		defer func() {
			By("cleaning up namespace")
			err := namespaceFixtures.Stop(ctx)
			Expect(err).ShouldNot(HaveOccurred())
		}()

		ingress := prepareServiceAndIngress(ns, "10.0.0.44", "resync.example.com", nil)

		By("reconciling with access enabled and a resync interval")
		recorder := record.NewFakeRecorder(100)
		tunnelClient := &recordingTunnelClient{}
		access := exposure.AccessDefaults{Enabled: true, ResyncInterval: 5 * time.Minute}
		result, err := newController(ns, recorder, tunnelClient, access).Reconcile(ctx, requestFor(ingress))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{RequeueAfter: 5 * time.Minute}))
		Expect(tunnelClient.exposures).Should(HaveLen(1))

		By("reconciling with access disabled")
		result, err = newController(ns, recorder, tunnelClient, exposure.AccessDefaults{Enabled: false}).Reconcile(ctx, requestFor(ingress))
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{}))
	})
})
