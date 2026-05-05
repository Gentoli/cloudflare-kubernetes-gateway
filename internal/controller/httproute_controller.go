package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/dns"
	"github.com/cloudflare/cloudflare-go/v6/zero_trust"
	"github.com/cloudflare/cloudflare-go/v6/zones"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HTTPRouteReconciler reconciles a HTTPRoute object
type HTTPRouteReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways/status,verbs=get;update
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes/status,verbs=get;update
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=backendtlspolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.18.2/pkg/reconcile
//
//nolint:gocyclo
func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// TODO delete DNS records. load all hostnames via tunnel ID in comment? but can't get DNS zone...
	target := &gatewayv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, target); err != nil {
		log.Error(err, "Failed to get HTTPRoute")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	defer func() {
		if updateErr := r.Status().Update(ctx, target); updateErr != nil {
			log.Error(updateErr, "Failed to update HTTPRoute status")
		}
	}()

	target.Status.Parents = []gatewayv1.RouteParentStatus{}
	gateways := []gatewayv1.Gateway{}

	for _, parentRef := range target.Spec.ParentRefs {
		namespace := target.ObjectMeta.Namespace
		if parentRef.Namespace != nil {
			namespace = string(*parentRef.Namespace)
		}
		gateway := &gatewayv1.Gateway{}
		if err := r.Get(ctx, types.NamespacedName{
			Namespace: namespace,
			Name:      string(parentRef.Name),
		}, gateway); err != nil {
			log.Error(err, "Failed to get Gateway")
			return ctrl.Result{}, err
		}
		gateways = append(gateways, *gateway)

		target.Status.Parents = append(target.Status.Parents, gatewayv1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: "github.com/pl4nty/cloudflare-kubernetes-gateway",
			Conditions: []metav1.Condition{
				{
					Type:               string(gatewayv1.RouteConditionAccepted),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.RouteReasonAccepted),
					Message:            "Route accepted",
					ObservedGeneration: target.Generation,
					LastTransitionTime: metav1.Now(),
				},
			},
		})
	}

	hostnames := target.Spec.Hostnames

	routes := &gatewayv1.HTTPRouteList{}
	if err := r.List(ctx, routes); err != nil {
		log.Error(err, "Failed to list HTTPRoutes")
		return ctrl.Result{}, err
	}

	for _, gateway := range gateways {
		setCondition := func(condType string, status metav1.ConditionStatus, reason, message string) {
			if target == nil || len(target.Status.Parents) == 0 {
				return
			}
			for i, p := range target.Status.Parents {
				ns1 := target.Namespace
				if p.ParentRef.Namespace != nil {
					ns1 = string(*p.ParentRef.Namespace)
				}
				if ns1 == gateway.Namespace && string(p.ParentRef.Name) == gateway.Name {
					meta.SetStatusCondition(&target.Status.Parents[i].Conditions, metav1.Condition{
						Type:               condType,
						Status:             status,
						Reason:             reason,
						Message:            message,
						ObservedGeneration: target.Generation,
					})
					break
				}
			}
		}

		// check target is in scope
		gatewayClass := &gatewayv1.GatewayClass{}
		if err := r.Get(ctx, types.NamespacedName{
			Name: string(gateway.Spec.GatewayClassName),
		}, gatewayClass); err != nil {
			log.Error(err, "Failed to get GatewayClasses")
			return ctrl.Result{}, err
		}

		if gatewayClass.Spec.ControllerName != "github.com/pl4nty/cloudflare-kubernetes-gateway" {
			continue
		}

		tunnelName := gateway.Name
		if val, ok := gateway.Annotations[AnnotationTunnelName]; ok {
			tunnelName = val
		}

		// search for sibling routes
		siblingRoutes := []gatewayv1.HTTPRoute{}
		for _, searchRoute := range routes.Items {
			for _, searchParent := range searchRoute.Spec.ParentRefs {
				namespace := searchRoute.ObjectMeta.Namespace
				if searchParent.Namespace != nil {
					namespace = string(*searchParent.Namespace)
				}
				if namespace == gateway.Namespace && string(searchParent.Name) == gateway.Name {
					siblingRoutes = append(siblingRoutes, searchRoute)
					break
				}
			}
		}

		// fan out to siblings
		type ingressData struct {
			hostname            string
			exactHostnameLen    int
			wildcardHostnameLen int
			path                string
			pathLen             int
			serviceURL          string
			useTLS              bool
			noTLSVerify         bool
			originServerName    string
			creationTimestamp   time.Time
			namespace           string
			name                string
			ruleIndex           int
		}
		var ingressList []ingressData

		for _, route := range siblingRoutes {
			for rIdx, rule := range route.Spec.Rules {
				paths := map[string]bool{}
				if len(rule.Matches) == 0 {
					paths["/"] = true
				}
				for _, match := range rule.Matches {
					if match.Path == nil {
						paths["/"] = true
					} else {
						paths[*match.Path.Value] = true
					}

					if match.Headers != nil {
						log.Info("HTTPRoute header match is not supported", match.Headers)
					}
				}

				// TODO implement this with rewrite rules? Core filters are a MUST in the spec
				if rule.Filters != nil {
					log.Info("HTTPRoute filters are not supported", rule.Filters)
				}

				type backendService struct {
					url              string
					useTLS           bool
					noTLSVerify      bool
					originServerName string
				}
				services := map[string]backendService{}
				for _, backend := range rule.BackendRefs {
					if backend.Port == nil {
						err := errors.New("HTTPRoute backend port is nil")
						log.Error(err, "HTTPRoute backend port is required and nil", backend)
						continue
					}

					var namespace string
					if backend.Namespace == nil {
						namespace = route.Namespace
					} else {
						namespace = string(*backend.Namespace)
					}

					var tlsPolicies gatewayv1.BackendTLSPolicyList
					if err := r.List(ctx, &tlsPolicies, client.InNamespace(namespace)); err != nil {
						log.Error(err, "Failed to list BackendTLSPolicies")
					}

					slices.SortFunc(tlsPolicies.Items, func(a, b gatewayv1.BackendTLSPolicy) int {
						if a.CreationTimestamp.Before(&b.CreationTimestamp) {
							return -1
						}
						if b.CreationTimestamp.Before(&a.CreationTimestamp) {
							return 1
						}
						return strings.Compare(a.Name, b.Name)
					})

					protocol := "http"
					useTLS := false
					noTLSVerify := true
					var originServerName string
					for _, policy := range tlsPolicies.Items {
						// Implementations SHOULD NOT support more than one targetRef at this time
						if len(policy.Spec.TargetRefs) == 0 {
							continue
						}
						target := policy.Spec.TargetRefs[0]
						if (target.Group == "" || target.Group == "core") && target.Kind == "Service" && string(target.Name) == string(backend.Name) {
							protocol = "https"
							useTLS = true
							if policy.Spec.Validation.WellKnownCACertificates != nil &&
								string(*policy.Spec.Validation.WellKnownCACertificates) == "cloudflare.com/origin-ca" {
								noTLSVerify = false
							}
							originServerName = string(policy.Spec.Validation.Hostname)
							break
						}
					}

					url := fmt.Sprintf("%s://%s.%s:%d", protocol, string(backend.Name), namespace, int32(*backend.Port))
					key := fmt.Sprintf("%s/%s:%d", namespace, string(backend.Name), int32(*backend.Port))
					if _, ok := services[key]; !ok {
						services[key] = backendService{
							url:              url,
							useTLS:           useTLS,
							noTLSVerify:      noTLSVerify,
							originServerName: originServerName,
						}
					}
				}

				// product of hostname, path, service
				hostnames := route.Spec.Hostnames
				if len(hostnames) == 0 {
					hostnames = []gatewayv1.Hostname{""}
				}
				for _, hostname := range hostnames {
					hostnameStr := string(hostname)
					exactHostnameLen := 0
					wildcardHostnameLen := 0
					if hostnameStr != "" {
						if strings.HasPrefix(hostnameStr, "*.") {
							wildcardHostnameLen = len(hostnameStr)
						} else {
							exactHostnameLen = len(hostnameStr)
						}
					}
					
					for path := range paths {
						pathLen := len(path)
						for _, service := range services {
							ingressList = append(ingressList, ingressData{
								hostname:            hostnameStr,
								exactHostnameLen:    exactHostnameLen,
								wildcardHostnameLen: wildcardHostnameLen,
								path:                path,
								pathLen:             pathLen,
								serviceURL:          service.url,
								useTLS:              service.useTLS,
								noTLSVerify:         service.noTLSVerify,
								originServerName:    service.originServerName,
								creationTimestamp:   route.CreationTimestamp.Time,
								namespace:           route.Namespace,
								name:                route.Name,
								ruleIndex:           rIdx,
							})
						}
					}
				}
			}
		}

		slices.SortFunc(ingressList, func(a, b ingressData) int {
			if a.exactHostnameLen != b.exactHostnameLen {
				return b.exactHostnameLen - a.exactHostnameLen
			}
			if a.wildcardHostnameLen != b.wildcardHostnameLen {
				return b.wildcardHostnameLen - a.wildcardHostnameLen
			}

			if a.pathLen != b.pathLen {
				return b.pathLen - a.pathLen
			}

			if !a.creationTimestamp.Equal(b.creationTimestamp) {
				if a.creationTimestamp.Before(b.creationTimestamp) {
					return -1
				}
				return 1
			}
			if a.namespace != b.namespace {
				return strings.Compare(a.namespace, b.namespace)
			}
			if a.name != b.name {
				return strings.Compare(a.name, b.name)
			}
			return a.ruleIndex - b.ruleIndex
		})

		ingress := []zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress{}
		for _, item := range ingressList {
			config := zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress{
				Path:    cloudflare.String(item.path),
				Service: cloudflare.String(item.serviceURL),
			}
			if item.hostname != "" {
				config.Hostname = cloudflare.String(item.hostname)
			}
			if item.useTLS {
				originRequest := zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngressOriginRequest{
					NoTLSVerify:    cloudflare.F(item.noTLSVerify),
					HTTP2Origin:    cloudflare.F(true),
					MatchSnItoHost: cloudflare.F(true),
				}
				if item.originServerName != "" {
					originRequest.OriginServerName = cloudflare.F(item.originServerName)
				}
				config.OriginRequest = cloudflare.F(originRequest)
			}
			ingress = append(ingress, config)
		}

		// last rule must be the catch-all
		ingress = append(ingress, zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress{
			Service: cloudflare.String("http_status:404"),
		})

		account, api, err := InitCloudflareApi(ctx, r.Client, string(gateway.Spec.GatewayClassName))
		if err != nil {
			log.Error(err, "Failed to initialize Cloudflare API")
			return ctrl.Result{}, err
		}

		tunnels, err := api.ZeroTrust.Tunnels.Cloudflared.List(ctx, zero_trust.TunnelCloudflaredListParams{
			AccountID: cloudflare.String(account),
			IsDeleted: cloudflare.Bool(false),
			Name:      cloudflare.String(tunnelName),
		})
		if err != nil {
			log.Error(err, "Failed to get tunnel from Cloudflare API")
			return ctrl.Result{}, err
		}
		if len(tunnels.Result) == 0 {
			log.Info("Tunnel doesn't exist yet, probably waiting for the Gateway controller. Retrying in 1 minute", "gateway", gateway.Name)
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		tunnel := tunnels.Result[0]

		// increment AttachedRoutes in each gateway listener status and set Addresses
		gatewayObj := &gatewayv1.Gateway{}
		gatewayRef := types.NamespacedName{
			Namespace: gateway.Namespace,
			Name:      gateway.Name,
		}
		if err := r.Get(ctx, gatewayRef, gatewayObj); err != nil {
			log.Error(err, "Failed to re-fetch gateway")
			return ctrl.Result{}, err
		}
		listeners := []gatewayv1.ListenerStatus{}
		for _, listener := range gatewayObj.Status.Listeners {
			listener.AttachedRoutes = int32(len(ingress))
			listeners = append(listeners, listener)
		}
		log.Info("Updating Gateway listeners", "AttachedRoutes", len(ingress))
		gatewayObj.Status.Listeners = listeners

		content := fmt.Sprintf("%s.cfargotunnel.com", tunnel.ID)
		hostnameAddressType := gatewayv1.HostnameAddressType
		gatewayObj.Status.Addresses = []gatewayv1.GatewayStatusAddress{{
			Type:  &hostnameAddressType,
			Value: content,
		}}

		tunnelOnly := false
		if val, ok := gatewayObj.Annotations["cloudflare-kubernetes-gateway.com/tunnel-only"]; ok && val == "true" {
			tunnelOnly = true
		}

		if tunnelOnly {
			meta.SetStatusCondition(&gatewayObj.Status.Conditions, metav1.Condition{
				Type:               "TunnelOnly",
				Status:             metav1.ConditionTrue,
				Reason:             "AnnotationSet",
				ObservedGeneration: gatewayObj.Generation,
				Message:            "Tunnel only mode enabled, skipping DNS record updates",
			})
		} else {
			meta.RemoveStatusCondition(&gatewayObj.Status.Conditions, "TunnelOnly")
		}

		if err := r.Status().Update(ctx, gatewayObj); err != nil {
			log.Error(err, "Failed to update Gateway status")
			return ctrl.Result{}, err
		}

		_, err = api.ZeroTrust.Tunnels.Cloudflared.Configurations.Update(ctx, tunnel.ID, zero_trust.TunnelCloudflaredConfigurationUpdateParams{
			AccountID: cloudflare.String(account),
			Config: cloudflare.F[zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig](
				zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfig{
					Ingress: cloudflare.F[[]zero_trust.TunnelCloudflaredConfigurationUpdateParamsConfigIngress](ingress),
				},
			),
		})
		if err != nil {
			log.Error(err, "Failed to update Tunnel configuration")
			setCondition("TunnelConfigured", metav1.ConditionFalse, "Failed", err.Error())
			return ctrl.Result{}, err
		}

		log.Info("Updated Tunnel configuration", "ingress", ingress)
		setCondition("TunnelConfigured", metav1.ConditionTrue, "TunnelConfigured", "Tunnel configuration updated")

		if tunnelOnly {
			setCondition("DNSConfigured", metav1.ConditionFalse, "TunnelOnly", "Tunnel only mode enabled, skipping DNS record updates")
			continue
		}

		// duplicate CNAMEs can't exist, so the last parentRef wins
		for _, gwHostname := range hostnames {
			hostname := string(gwHostname)
			zoneID, err := FindZoneID(hostname, ctx, api, account)
			if err != nil {
				return ctrl.Result{}, err
			}

			comment := "Managed by github.com/pl4nty/cloudflare-kubernetes-gateway"
			records, _ := api.DNS.Records.List(ctx, dns.RecordListParams{
				ZoneID:  cloudflare.String(zoneID),
				Proxied: cloudflare.Bool(true),
				Type:    cloudflare.F(dns.RecordListParamsTypeCNAME),
				Name:    cloudflare.F(dns.RecordListParamsName{Exact: cloudflare.String(hostname)}),
			})
			if len(records.Result) == 0 {
				_, err := api.DNS.Records.New(ctx, dns.RecordNewParams{
					ZoneID: cloudflare.String(zoneID),
					Body: dns.RecordNewParamsBodyUnion(dns.CNAMERecordParam{
						Proxied: cloudflare.Bool(true),
						Type:    cloudflare.F(dns.CNAMERecordTypeCNAME),
						Name:    cloudflare.F(hostname),
						Content: cloudflare.F(content),
						Comment: cloudflare.String(comment),
					}),
				})
				if err != nil {
					log.Error(err, "Failed to create DNS record", hostname, content)
					return ctrl.Result{}, err
				}
			} else {
				_, err := api.DNS.Records.Update(ctx, records.Result[0].ID, dns.RecordUpdateParams{
					ZoneID: cloudflare.String(zoneID),
					Body: dns.RecordUpdateParamsBodyUnion(dns.CNAMERecordParam{
						Proxied: cloudflare.Bool(true),
						Type:    cloudflare.F(dns.CNAMERecordTypeCNAME),
						Name:    cloudflare.F(hostname),
						Content: cloudflare.F(content),
						Comment: cloudflare.String(comment),
					}),
				})
				if err != nil {
					log.Error(err, "Failed to update DNS record", hostname, content)
					return ctrl.Result{}, err
				}
			}
		}
		log.Info("Updated DNS records", "hostnames", hostnames)
		setCondition("DNSConfigured", metav1.ConditionTrue, "DNSConfigured", "DNS records updated")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	pred := predicate.GenerationChangedPredicate{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		WithEventFilter(pred).
		Complete(r)
}

func FindZoneID(hostname string, ctx context.Context, api *cloudflare.Client, accountID string) (string, error) {
	log := log.FromContext(ctx)
	for parts := range len(strings.Split(hostname, ".")) {
		zoneName := strings.Join(strings.Split(hostname, ".")[parts:], ".")
		zones, err := api.Zones.List(ctx, zones.ZoneListParams{
			Account: cloudflare.F(zones.ZoneListParamsAccount{
				ID: cloudflare.String(accountID),
			}),
			Name:   cloudflare.String(zoneName),
			Status: cloudflare.F(zones.ZoneListParamsStatusActive),
		})
		if err != nil {
			log.Error(err, "Failed to list DNS zones")
			return "", err
		}
		if len(zones.Result) != 0 {
			return zones.Result[0].ID, nil
		}
	}
	err := errors.New("failed to discover DNS zone")
	log.Error(err, "Failed to discover parent DNS zone. Ensure Zone.DNS permission is configured", "hostname", hostname)
	return "", err
}
