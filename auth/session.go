package auth

import (
	"fmt"
	"sync"
	"time"
)

const openshiftSessionCookieName = "openshift-session-token"

type oldSession struct {
	token	string
	exp	time.Time
}
type SessionStore struct {
	byToken		map[string]*loginState
	byAge		[]oldSession
	maxSessions	int
	now		nowFunc
	mux		sync.Mutex
}

func NewSessionStore(maxSessions int) *SessionStore {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return &SessionStore{byToken: make(map[string]*loginState), maxSessions: maxSessions, now: defaultNow}
}
func (ss *SessionStore) addSession(ls *loginState) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	sessionToken := randomString(128)
	if ss.byToken[sessionToken] != nil {
		ss.deleteSession(sessionToken)
		return fmt.Errorf("Session token collision! THIS SHOULD NEVER HAPPEN! Token: %s", sessionToken)
	}
	ls.sessionToken = sessionToken
	ss.mux.Lock()
	ss.byToken[sessionToken] = ls
	ss.byAge = append(ss.byAge, oldSession{sessionToken, ls.exp})
	ss.mux.Unlock()
	return nil
}
func (ss *SessionStore) getSession(token string) *loginState {
	_logClusterCodePath()
	defer _logClusterCodePath()
	ss.mux.Lock()
	defer ss.mux.Unlock()
	return ss.byToken[token]
}
func (ss *SessionStore) deleteSession(token string) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	ss.mux.Lock()
	defer ss.mux.Unlock()
	delete(ss.byToken, token)
	for i := 0; i < len(ss.byAge); i++ {
		s := ss.byAge[i]
		if s.token == token {
			ss.byAge = append(ss.byAge[:i], ss.byAge[i+1:]...)
			return nil
		}
	}
	log.Errorf("ss.byAge did not contain session %v", token)
	return fmt.Errorf("ss.byAge did not contain session %v", token)
}
func (ss *SessionStore) pruneSessions() {
	_logClusterCodePath()
	defer _logClusterCodePath()
	ss.mux.Lock()
	defer ss.mux.Unlock()
	expired := 0
	for i := 0; i < len(ss.byAge); i++ {
		s := ss.byAge[i]
		if s.exp.Sub(ss.now()) < 0 {
			delete(ss.byToken, s.token)
			ss.byAge = append(ss.byAge[:i], ss.byAge[i+1:]...)
			expired++
		}
	}
	log.Debugf("Pruned %v expired sessions.", expired)
	toRemove := len(ss.byAge) - ss.maxSessions
	if toRemove > 0 {
		log.Debugf("Still too many sessions. Pruning oldest %v sessions...", toRemove)
		for _, s := range ss.byAge[:toRemove] {
			delete(ss.byToken, s.token)
		}
		ss.byAge = ss.byAge[toRemove:]
	}
	if expired+toRemove > 0 {
		log.Debugf("Pruned %v old sessions.", expired+toRemove)
	}
}
