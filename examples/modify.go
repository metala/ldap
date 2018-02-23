// +build ignore

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/mark-rushakoff/ldapserver"
)

var (
	LdapServer string = "localhost"
	LdapPort   uint16 = 389
	BaseDN     string = "dc=enterprise,dc=org"
	BindDN     string = "cn=admin,dc=enterprise,dc=org"
	BindPW     string = "enterprise"
	Filter     string = "(cn=kirkj)"
)

func search(l *ldapserver.Conn, filter string, attributes []string) (*ldapserver.Entry, *ldapserver.Error) {
	search := ldapserver.NewSearchRequest(
		BaseDN,
		ldapserver.ScopeWholeSubtree, ldapserver.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := l.Search(search)
	if err != nil {
		log.Fatalf("ERROR: %s\n", err)
		return nil, err
	}

	log.Printf("Search: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
	if len(sr.Entries) == 0 {
		return nil, ldapserver.NewError(ldapserver.ErrorDebugging, errors.New(fmt.Sprintf("no entries found for: %s", filter)))
	}
	return sr.Entries[0], nil
}

func main() {
	l, err := ldapserver.Dial("tcp", fmt.Sprintf("%s:%d", LdapServer, LdapPort))
	if err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
	}
	defer l.Close()
	// l.Debug = true

	l.Bind(BindDN, BindPW)

	log.Printf("The Search for Kirk ... %s\n", Filter)
	entry, err := search(l, Filter, []string{})
	if err != nil {
		log.Fatal("could not get entry")
	}
	entry.PrettyPrint(0)

	log.Printf("modify the mail address and add a description ... \n")
	modify := ldapserver.NewModifyRequest(entry.DN)
	modify.Add("description", []string{"Captain of the USS Enterprise"})
	modify.Replace("mail", []string{"captain@enterprise.org"})
	if err := l.Modify(modify); err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
	}

	entry, err = search(l, Filter, []string{})
	if err != nil {
		log.Fatal("could not get entry")
	}
	entry.PrettyPrint(0)

	log.Printf("reset the entry ... \n")
	modify = ldapserver.NewModifyRequest(entry.DN)
	modify.Delete("description", []string{})
	modify.Replace("mail", []string{"james.kirk@enterprise.org"})
	if err := l.Modify(modify); err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
	}

	entry, err = search(l, Filter, []string{})
	if err != nil {
		log.Fatal("could not get entry")
	}
	entry.PrettyPrint(0)
}
