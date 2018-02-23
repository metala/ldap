package main

import (
	"github.com/mark-rushakoff/ldapserver"
	"log"
	"net"
)

/////////////
// Sample searches you can try against this simple LDAP server:
//
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com'
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com' 'cn=ned'
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com' 'uidnumber=5000'
/////////////

///////////// Run a simple LDAP server
func main() {
	s := ldapserver.NewServer()

	// register Bind and Search function handlers
	handler := ldapHandler{}
	s.BindFunc("", handler)
	s.SearchFunc("", handler)

	// start the server
	listen := "localhost:3389"
	log.Printf("Starting example LDAP server on %s", listen)
	if err := s.ListenAndServe(listen); err != nil {
		log.Fatal("LDAP Server Failed: %s", err.Error())
	}
}

type ldapHandler struct {
}

///////////// Allow anonymous binds only
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldapserver.LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldapserver.LDAPResultSuccess, nil
	}
	return ldapserver.LDAPResultInvalidCredentials, nil
}

///////////// Return some hardcoded search results - we'll respond to any baseDN for testing
func (h ldapHandler) Search(boundDN string, searchReq ldapserver.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
	entries := []*ldapserver.Entry{
		&ldapserver.Entry{"cn=ned," + searchReq.BaseDN, []*ldapserver.EntryAttribute{
			&ldapserver.EntryAttribute{"cn", []string{"ned"}},
			&ldapserver.EntryAttribute{"uidNumber", []string{"5000"}},
			&ldapserver.EntryAttribute{"accountStatus", []string{"active"}},
			&ldapserver.EntryAttribute{"uid", []string{"ned"}},
			&ldapserver.EntryAttribute{"description", []string{"ned"}},
			&ldapserver.EntryAttribute{"objectClass", []string{"posixAccount"}},
		}},
		&ldapserver.Entry{"cn=trent," + searchReq.BaseDN, []*ldapserver.EntryAttribute{
			&ldapserver.EntryAttribute{"cn", []string{"trent"}},
			&ldapserver.EntryAttribute{"uidNumber", []string{"5005"}},
			&ldapserver.EntryAttribute{"accountStatus", []string{"active"}},
			&ldapserver.EntryAttribute{"uid", []string{"trent"}},
			&ldapserver.EntryAttribute{"description", []string{"trent"}},
			&ldapserver.EntryAttribute{"objectClass", []string{"posixAccount"}},
		}},
	}
	return ldapserver.ServerSearchResult{entries, []string{}, []ldapserver.Control{}, ldapserver.LDAPResultSuccess}, nil
}
