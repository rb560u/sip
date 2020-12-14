package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"text/template"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	airshipv1 "sipcluster/pkg/api/v1"
	//v1 "sipcluster/pkg/api/v1"
	airshipvms "sipcluster/pkg/vbmh"
)

const (
	// ConfigSecretName name of the haproxy config secret name/volume/mount
	ConfigSecretName = "haproxy-config"
	// DefaultBalancerImage is the image that will be used as load balancer
	DefaultBalancerImage = "busybox"
)

// InfraService generalizes inftracture services
type InfraService interface {
	Deploy() error
	Finalize() error
	Type() airshipv1.InfraService
}

// ServiceSet provides access to infrastructure services
type ServiceSet struct {
	logger logr.Logger

	sip      airshipv1.SIPCluster
	machines *airshipvms.MachineList
	client   client.Client

	services map[airshipv1.InfraService]InfraService
}

// NewServiceSet return new instance of ServiceSet
func NewServiceSet(
	logger logr.Logger,
	sip airshipv1.SIPCluster,
	machines *airshipvms.MachineList,
	client client.Client) ServiceSet {
	logger = logger.WithValues("SIPCluster", types.NamespacedName{Name: sip.GetNamespace(), Namespace: sip.GetName()})

	return ServiceSet{
		logger:   logger,
		sip:      sip,
		client:   client,
		machines: machines,
	}
}

// LoadBalancer returns loadbalancer service
func (ss ServiceSet) LoadBalancer() (InfraService, error) {
	lb, ok := ss.services[airshipv1.LoadBalancerService]
	if !ok {
		ss.logger.Info("sip cluster doesn't have loadbalancer infrastructure service defined")
	}
	return lb, fmt.Errorf("Loadbalancer service is not defined for sip cluster '%s'/'%s'",
		ss.sip.GetNamespace(),
		ss.sip.GetName())
}

// ServiceList returns all services defined in Set
func (ss ServiceSet) ServiceList() []InfraService {
	var serviceList []InfraService
	for serviceType, serviceConfig := range ss.sip.Spec.InfraServices {
		switch serviceType {
		case airshipv1.LoadBalancerService:
			ss.logger.Info("Service of type '%s' is defined", "service type", serviceType)
			serviceList = append(serviceList,
				newLB(ss.sip.GetName(),
					ss.sip.GetNamespace(),
					ss.logger,
					serviceConfig,
					ss.machines,
					ss.client))
		default:
			ss.logger.Info("Service of type '%s' is unknown to SIPCluster controller", "service type", serviceType)
		}
	}
	return serviceList
}

func newLB(name, namespace string,
	logger logr.Logger,
	config airshipv1.InfraConfig,
	machines *airshipvms.MachineList,
	client client.Client) loadBalancer {
	return loadBalancer{
		sipName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
		logger:   logger,
		config:   config,
		machines: machines,
		client:   client,
	}
}

type loadBalancer struct {
	client   client.Client
	sipName  types.NamespacedName
	logger   logr.Logger
	config   airshipv1.InfraConfig
	machines *airshipvms.MachineList
}

func (lb loadBalancer) Deploy() error {
	// Attempt to create configmap
	newcm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "haproxy-config",
			Namespace: "sipcluster-system",
		},
		Data: map[string]string{
			"haproxy.cfg": haproxyConfig,
		},
	}
	lb.client.Create(context.Background(), newcm)

	// Create haproxy pod
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "sipcluster-system",
			Name:      "haproxy",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: "docker-open-nc.zc1.cti.att.com/upstream-local/haproxy@sha256:019211bef0f81d5ce95df4ef1e252d37a356eeed28eb7247da2b324fab251ad7",
					Name:  "haproxy",
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "haproxy-cfg",
							MountPath: "/usr/local/etc/haproxy/haproxy.cfg",
							SubPath:   "haproxy.cfg",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "haproxy-cfg",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "haproxy-config",
							},
							//Items: []corev1.KeyToPath{
							//Key: "haproxy.conf",
							//Path: "haproxy-config",
							//},
						},
					},
				},
			},
		},
	}
	lb.client.Create(context.Background(), pod)
	/*if lb.config.Image == "" {
		lb.config.Image = DefaultBalancerImage
	}

	pod, secret, err := lb.generatePodAndSecret()
	if err != nil {
		return err
	}

	//lb.logger.Info("Applying loadbalancer secret", "secret", secret.GetNamespace()+"/"+secret.GetName())
	err = applyRuntimeObject(client.ObjectKey{Name: secret.GetName(), Namespace: secret.GetNamespace()}, secret, lb.client)
	if err != nil {
		return err
	}

	//lb.logger.Info("Applying loadbalancer pod", "pod", pod.GetNamespace()+"/"+pod.GetName())
	err = applyRuntimeObject(client.ObjectKey{Name: pod.GetName(), Namespace: pod.GetNamespace()}, pod, lb.client)
	if err != nil {
		return err
	}*/
	return nil
}

func (lb loadBalancer) Finalize() error {
	return nil
}

// Type type of the service
func (lb loadBalancer) Type() airshipv1.InfraService {
	return airshipv1.LoadBalancerService
}

func (lb loadBalancer) generatePodAndSecret() (*corev1.Pod, *corev1.Secret, error) {
	secret, err := lb.generateSecret()
	if err != nil {
		return nil, nil, err
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      lb.sipName.Name + "-load-balancer",
			Namespace: lb.sipName.Namespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "balancer",
					Image:   lb.config.Image,
					Command: []string{"sh", "-c", "set -xe while true; do cat /cfg/MyData; sleep 20; done"},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      ConfigSecretName,
							MountPath: "/cfg",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: ConfigSecretName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: secret.GetName(),
						},
					},
				},
			},
		},
	}

	return pod, secret, nil

}

func (lb loadBalancer) generateSecret() (*corev1.Secret, error) {

	p := proxy{
		FrontPort: 6443,
		Backends:  make([]backend, 0),
	}
	for _, machine := range lb.machines.Machines {
		name := machine.BMH.Name
		namespace := machine.BMH.Namespace
		ip, exists := machine.Data.IPOnInterface[lb.config.NodeInterface]
		if !exists {
			lb.logger.Info("Machine does not have backend interface to be forwarded to",
				"interface", lb.config.NodeInterface,
				"machine", namespace+"/"+name,
			)
			continue
		}
		p.Backends = append(p.Backends, backend{IP: ip, Name: machine.BMH.Name, Port: 6443})
	}

	secretData, err := generateTemplate(p)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      lb.sipName.Name + "-load-balancer",
			Namespace: lb.sipName.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			ConfigSecretName: secretData,
		},
	}, nil
}

type proxy struct {
	FrontPort int
	Backends  []backend
}

type backend struct {
	IP   string
	Name string
	Port int
}

func generateTemplate(p proxy) ([]byte, error) {
	tmpl, err := template.New("haproxy-config").Parse(defaultTemplate)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer([]byte{})
	if err := tmpl.Execute(w, p); err != nil {
		return nil, err
	}

	rendered := w.Bytes()
	result := make([]byte, base64.StdEncoding.EncodedLen(len(rendered)))
	base64.StdEncoding.Encode(result, rendered)
	return result, nil
}

func applyRuntimeObject(key client.ObjectKey, obj runtime.Object, c client.Client) error {
	getObj := obj.DeepCopyObject()
	ctx := context.Background()
	switch err := c.Get(ctx, key, getObj); {
	case apierror.IsNotFound(err):
		return c.Create(ctx, obj)
	case err == nil:
		return c.Update(ctx, obj)
	default:
		return err
	}
}

var defaultTemplate = `global
  log /dev/stdout local0
  log /dev/stdout local1 notice
  daemon
defaults
  log global
  mode tcp
  option dontlognull
  # TODO: tune these
  timeout connect 5000
  timeout client 50000
  timeout server 50000
frontend control-plane
  bind *:{{ .FrontPort }}
  default_backend kube-apiservers
backend kube-apiservers
  option httpchk GET /healthz
{{- range .Backends }}
{{- $backEnd := . }}
  server {{ $backEnd.Name }} {{ $backEnd.IP }}:{{ $backEnd.Port }} check check-ssl verify none
{{ end -}}
`

// haproxy.cfg
const haproxyConfig = `global
     stats timeout 30s
     user root
     group root
     daemon
     # Default SSL material locations
     ca-base /etc/ssl/certs
     crt-base /etc/ssl/private
     # Default ciphers to use on SSL-enabled listening sockets.
     # For more information, see ciphers(1SSL). This list is from:
     #  https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
     # An alternative list with additional directives can be obtained from
     #  https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=haproxy
     ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS
     ssl-default-bind-options no-sslv3
defaults
       log     global
       mode    http
       option  httplog
       option  dontlognull
       timeout connect 5000
       timeout client  50000
       timeout server  50000
frontend myfrontend
 bind *:80
 mode http
 default_backend mybackend
backend mybackend
 mode http
 balance roundrobin
 option httpchk HEAD / # checks against the index page
 server web1 172.17.0.2:80 check weight 10
 server web2 172.17.0.3:80 check weight 20
`
