package auth

import (
	"encoding/json"
	"fmt"
	"time"
)

type loginState struct {
	UserID		string
	Name		string
	Email		string
	exp		time.Time
	now		nowFunc
	sessionToken	string
	rawToken	string
}
type LoginJSON struct {
	UserID	string	`json:"userID"`
	Name	string	`json:"name"`
	Email	string	`json:"email"`
	Exp	int64	`json:"exp"`
}

func newLoginState(rawToken string, claims []byte) (*loginState, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	ls := &loginState{now: defaultNow, rawToken: rawToken}
	var c struct {
		Subject	string		`json:"sub"`
		Expiry	jsonTime	`json:"exp"`
		Email	string		`json:"email"`
		Name	string		`json:"name"`
	}
	if err := json.Unmarshal(claims, &c); err != nil {
		return nil, fmt.Errorf("error getting claims from token: %v", err)
	}
	if c.Subject == "" {
		return nil, fmt.Errorf("token missing require claim 'sub'")
	}
	ls.UserID = c.Subject
	ls.Email = c.Email
	ls.exp = time.Time(c.Expiry)
	ls.Name = c.Name
	return ls, nil
}
func (ls *loginState) toLoginJSON() LoginJSON {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return LoginJSON{UserID: ls.UserID, Name: ls.Name, Email: ls.Email, Exp: ls.exp.Unix()}
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64
	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}
