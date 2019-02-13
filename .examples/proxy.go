package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"sync"

	ldapserver "github.com/metala/ldap"
)

type ldapHandler struct {
	sessions   map[string]session
	lock       sync.Mutex
	ldapServer string
	ldapPort   int
}

///////////// Run a simple LDAP proxy
func main() {
	s := ldapserver.NewServer()

	handler := ldapHandler{
		sessions:   make(map[string]session),
		ldapServer: "localhost",
		ldapPort:   3389,
	}
	s.BindFunc("", handler)
	s.SearchFunc("", handler)
	s.CloseFunc("", handler)

	// start the server
	if err := s.ListenAndServe("localhost:3388"); err != nil {
		log.Fatal("LDAP Server Failed: %s", err.Error())
	}
}

/////////////
type session struct {
	id   string
	c    net.Conn
	ldap *ldapserver.Conn
}

func (h ldapHandler) getSession(conn net.Conn) (session, error) {
	id := connID(conn)
	h.lock.Lock()
	s, ok := h.sessions[id] // use server connection if it exists
	h.lock.Unlock()
	if !ok { // open a new server connection if not
		l, err := ldapserver.Dial("tcp", fmt.Sprintf("%s:%d", h.ldapServer, h.ldapPort))
		if err != nil {
			return session{}, err
		}
		s = session{id: id, c: conn, ldap: l}
		h.lock.Lock()
		h.sessions[s.id] = s
		h.lock.Unlock()
	}
	return s, nil
}

/////////////
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint64, error) {
	s, err := h.getSession(conn)
	if err != nil {
		return ldapserver.LDAPResultOperationsError, err
	}
	if err := s.ldap.Bind(bindDN, bindSimplePw); err != nil {
		return ldapserver.LDAPResultOperationsError, err
	}
	return ldapserver.LDAPResultSuccess, nil
}

/////////////
func (h ldapHandler) Search(boundDN string, searchReq ldapserver.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
	s, err := h.getSession(conn)
	if err != nil {
		return ldapserver.ServerSearchResult{ResultCode: ldapserver.LDAPResultOperationsError}, nil
	}
	search := ldapserver.NewSearchRequest(
		searchReq.BaseDN,
		ldapserver.ScopeWholeSubtree, ldapserver.NeverDerefAliases, 0, 0, false,
		searchReq.Filter,
		searchReq.Attributes,
		nil)
	sr, err := s.ldap.Search(search)
	if err != nil {
		return ldapserver.ServerSearchResult{}, err
	}
	//log.Printf("P: Search OK: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
	return ldapserver.ServerSearchResult{sr.Entries, []string{}, []ldapserver.Control{}, ldapserver.LDAPResultSuccess}, nil
}
func (h ldapHandler) Close(conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, connID(conn))
	return nil
}
func connID(conn net.Conn) string {
	h := sha256.New()
	h.Write([]byte(conn.LocalAddr().String() + conn.RemoteAddr().String()))
	sha := fmt.Sprintf("% x", h.Sum(nil))
	return string(sha)
}
