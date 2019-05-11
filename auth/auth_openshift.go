package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"golang.org/x/oauth2"
	"github.com/openshift/console/pkg/proxy"
)

type openShiftAuth struct {
	cookiePath			string
	secureCookies		bool
	kubeAdminLogoutURL	string
}
type openShiftConfig struct {
	k8sClient		*http.Client
	oauthClient		*http.Client
	issuerURL		string
	cookiePath		string
	secureCookies	bool
}

func validateAbsURL(value string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	ur, err := url.Parse(value)
	if err != nil {
		return err
	}
	if ur == nil || ur.String() == "" || ur.Scheme == "" || ur.Host == "" {
		return fmt.Errorf("url is not absolute: %v", ur)
	}
	return nil
}
func newOpenShiftAuth(ctx context.Context, c *openShiftConfig) (oauth2.Endpoint, *openShiftAuth, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	wellKnownURL := strings.TrimSuffix(c.issuerURL, "/") + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequest(http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return oauth2.Endpoint{}, nil, err
	}
	resp, err := c.k8sClient.Do(req.WithContext(ctx))
	if err != nil {
		return oauth2.Endpoint{}, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return oauth2.Endpoint{}, nil, fmt.Errorf("discovery through endpoint %s failed: %s", wellKnownURL, resp.Status)
	}
	var metadata struct {
		Issuer	string	`json:"issuer"`
		Auth	string	`json:"authorization_endpoint"`
		Token	string	`json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return oauth2.Endpoint{}, nil, fmt.Errorf("discovery through endpoint %s failed to decode body: %v", wellKnownURL, err)
	}
	if err := validateAbsURL(metadata.Issuer); err != nil {
		return oauth2.Endpoint{}, nil, err
	}
	if err := validateAbsURL(metadata.Auth); err != nil {
		return oauth2.Endpoint{}, nil, err
	}
	if err := validateAbsURL(metadata.Token); err != nil {
		return oauth2.Endpoint{}, nil, err
	}
	req, err = http.NewRequest(http.MethodHead, metadata.Issuer, nil)
	if err != nil {
		return oauth2.Endpoint{}, nil, err
	}
	resp, err = c.oauthClient.Do(req.WithContext(ctx))
	if err != nil {
		return oauth2.Endpoint{}, nil, fmt.Errorf("request to OAuth issuer endpoint %s failed: %v", metadata.Token, err)
	}
	defer resp.Body.Close()
	kubeAdminLogoutURL := proxy.SingleJoiningSlash(metadata.Issuer, "/logout")
	return oauth2.Endpoint{AuthURL: metadata.Auth, TokenURL: metadata.Token}, &openShiftAuth{c.cookiePath, c.secureCookies, kubeAdminLogoutURL}, nil
}
func (o *openShiftAuth) login(w http.ResponseWriter, token *oauth2.Token) (*loginState, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if token.AccessToken == "" {
		return nil, fmt.Errorf("token response did not contain an access token %#v", token)
	}
	ls := &loginState{rawToken: token.AccessToken}
	expiresIn := (time.Hour * 24).Seconds()
	if !token.Expiry.IsZero() {
		expiresIn = token.Expiry.Sub(time.Now()).Seconds()
	}
	cookie := http.Cookie{Name: openshiftSessionCookieName, Value: ls.rawToken, MaxAge: int(expiresIn), HttpOnly: true, Path: o.cookiePath, Secure: o.secureCookies}
	http.SetCookie(w, &cookie)
	return ls, nil
}
func (o *openShiftAuth) logout(w http.ResponseWriter, r *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cookie := http.Cookie{Name: openshiftSessionCookieName, Value: "", MaxAge: 0, HttpOnly: true, Path: o.cookiePath, Secure: o.secureCookies}
	http.SetCookie(w, &cookie)
	w.WriteHeader(http.StatusNoContent)
}
func getOpenShiftUser(r *http.Request) (*User, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cookie, err := r.Cookie(openshiftSessionCookieName)
	if err != nil {
		return nil, err
	}
	if cookie.Value == "" {
		return nil, fmt.Errorf("unauthenticated")
	}
	return &User{Token: cookie.Value}, nil
}
func (o *openShiftAuth) getKubeAdminLogoutURL() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return o.kubeAdminLogoutURL
}
