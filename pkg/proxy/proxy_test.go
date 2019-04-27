package proxy

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"github.com/gorilla/websocket"
)

func TestProxyWebsocket(t *testing.T) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	proxyURL, closer, err := startProxyServer(t)
	if err != nil {
		t.Fatalf("problem setting up proxy server: %v", err)
	}
	defer closer()
	dialer := &websocket.Dialer{Subprotocols: []string{"base64.binary.k8s.io"}}
	headers := http.Header{}
	headers.Add("Origin", "http://localhost")
	ws, _, err := dialer.Dial(toWSScheme(proxyURL)+"/proxy/lower", headers)
	if err != nil {
		t.Fatalf("error connecting to /proxy/lower as websocket: %v", err)
		return
	}
	defer ws.Close()
	ws.WriteMessage(websocket.TextMessage, []byte("HI"))
	res, err := readStringFromWS(ws)
	if err != nil {
		t.Fatalf("error reading from websocket: %v", err)
	}
	if res != "hi" {
		t.Errorf("res == %v, want %v", res, "hi")
	}
}
func TestProxyHTTP(t *testing.T) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	proxyURL, closer, err := startProxyServer(t)
	if err != nil {
		t.Fatalf("problem setting up proxy server: %v", err)
	}
	defer closer()
	res, err := http.Get(proxyURL + "/proxy/static")
	if err != nil {
		t.Fatalf("err GETting from /proxy/static: %v", err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("err reading res.Body: %v", err)
	}
	if string(body) != "static" {
		t.Errorf("string(body) == %q, want %q", string(body), "static")
	}
}
func TestProxyDecodeSubprotocol(t *testing.T) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	tests := []struct {
		encoded	string
		decoded	string
	}{{encoded: "8J2SnPCdkpzwnZKc8J2SnA__", decoded: "𝒜𝒜𝒜𝒜"}, {encoded: "bm9uLXByaXY_", decoded: "non-priv"}, {encoded: "8J2SnPCfjYbwn42RQPCfjYbwn42R4oiGw6XLhs+GzrHOtc+Czr-Ouc6xz4nOp86oz4zOufCdkpzOm86azqPOs8+BzrvOus+DzpLOps6+4oiC", decoded: "𝒜🍆🍑@🍆🍑∆åˆφαεςοιαωΧΨόι𝒜ΛΚΣγρλκσΒΦξ∂"}}
	for _, test := range tests {
		decoded, err := decodeSubprotocol(test.encoded)
		if err != nil {
			t.Fatalf("err decoding subprotocol %v: %v", test.encoded, err)
		}
		if decoded != test.decoded {
			t.Errorf("decoded %v as %v but expected %v", test.encoded, decoded, test.decoded)
		}
	}
}
func startProxyServer(t *testing.T) (string, func(), error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	mux := http.NewServeMux()
	mux.HandleFunc("/lower", lowercaseServer(t))
	mux.HandleFunc("/static", staticServer)
	server := httptest.NewServer(mux)
	targetURL, err := url.Parse(server.URL)
	if err != nil {
		return "", nil, err
	}
	targetURL.Path = ""
	p := NewProxy(&Config{Endpoint: targetURL})
	proxyMux := http.NewServeMux()
	proxyMux.Handle("/proxy/", http.StripPrefix("/proxy/", p))
	proxyServer := httptest.NewServer(proxyMux)
	return proxyServer.URL, func() {
		proxyServer.Close()
		server.Close()
	}, nil
}
func lowercaseServer(t *testing.T) func(w http.ResponseWriter, r *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	upgrader := &websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
		return true
	}}
	return func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade websocket to client: '%v'", err)
			return
		}
		for {
			str, err := readStringFromWS(ws)
			if err != nil {
				t.Fatalf("err reading from websocket: %v", err)
			}
			err = ws.WriteMessage(websocket.TextMessage, []byte(strings.ToLower(str)))
			if err != nil {
				t.Fatalf("err reading to websocket: %v", err)
			}
			return
		}
	}
}
func staticServer(res http.ResponseWriter, req *http.Request) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	res.Write([]byte("static"))
}
func readStringFromWS(ws *websocket.Conn) (string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	_, buf, err := ws.ReadMessage()
	if err != nil {
		return "", err
	}
	return string(buf), nil
}
func toWSScheme(url_ string) string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	parsed, err := url.Parse(url_)
	if err != nil {
		panic(err)
	}
	parsed.Scheme = "ws"
	return parsed.String()
}
