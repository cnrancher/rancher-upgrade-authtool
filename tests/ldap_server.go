package tests

//
//import (
//	"fmt"
//	"net"
//	"strings"
//
//	"github.com/nmcclain/ldap"
//)
//
//var mockUserList = []*ldap.Entry{
//	&ldap.Entry{
//		DN: "uid=admin,ou=test,dc=example,dc=com",
//		Attributes: []*ldap.EntryAttribute{
//			&ldap.EntryAttribute{"uid", []string{"admin"}},
//			&ldap.EntryAttribute{"cn", []string{"admin"}},
//			&ldap.EntryAttribute{"userPassword", []string{"admin"}},
//			&ldap.EntryAttribute{"objectClass", []string{"inetOrgPerson"}},
//			&ldap.EntryAttribute{"entryUUID", []string{"aa-bb-cc-admin"}},
//		},
//	},
//	&ldap.Entry{
//		DN: "uid=user1,ou=test,dc=example,dc=com",
//		Attributes: []*ldap.EntryAttribute{
//			&ldap.EntryAttribute{"uid", []string{"user1"}},
//			&ldap.EntryAttribute{"cn", []string{"user1"}},
//			&ldap.EntryAttribute{"userPassword", []string{"test"}},
//			&ldap.EntryAttribute{"objectClass", []string{"inetOrgPerson"}},
//			&ldap.EntryAttribute{"memberOf", []string{"cn=group1,ou=rancher,dc=example,dc=com"}},
//			&ldap.EntryAttribute{"entryUUID", []string{"aa-bb-cc-user1"}},
//		},
//	},
//	&ldap.Entry{
//		DN: "uid=user2,ou=test,dc=example,dc=com",
//		Attributes: []*ldap.EntryAttribute{
//			&ldap.EntryAttribute{"uid", []string{"user2"}},
//			&ldap.EntryAttribute{"cn", []string{"user2"}},
//			&ldap.EntryAttribute{"userPassword", []string{"test"}},
//			&ldap.EntryAttribute{"objectClass", []string{"inetOrgPerson"}},
//			&ldap.EntryAttribute{"memberOf", []string{"cn=group2,ou=rancher,dc=example,dc=com"}},
//			&ldap.EntryAttribute{"entryUUID", []string{"aa-bb-cc-user2"}},
//		},
//	},
//	&ldap.Entry{
//		DN: "uid=user3,ou=test,dc=example,dc=com",
//		Attributes: []*ldap.EntryAttribute{
//			&ldap.EntryAttribute{"uid", []string{"user3"}},
//			&ldap.EntryAttribute{"cn", []string{"user3"}},
//			&ldap.EntryAttribute{"userPassword", []string{"test"}},
//			&ldap.EntryAttribute{"objectClass", []string{"inetOrgPerson"}},
//			&ldap.EntryAttribute{"entryUUID", []string{"aa-bb-cc-user3"}},
//		},
//	},
//	&ldap.Entry{
//		DN: "uid=user4,ou=test,dc=example,dc=com",
//		Attributes: []*ldap.EntryAttribute{
//			&ldap.EntryAttribute{"uid", []string{"user4"}},
//			&ldap.EntryAttribute{"cn", []string{"user4"}},
//			&ldap.EntryAttribute{"userPassword", []string{"test"}},
//			&ldap.EntryAttribute{"objectClass", []string{"inetOrgPerson"}},
//			&ldap.EntryAttribute{"entryUUID", []string{"aa-bb-cc-user4"}},
//		},
//	},
//}
//
//var mockGroupList = []*ldap.Entry{
//	&ldap.Entry{"cn=group1,ou=test,dc=example,dc=com", []*ldap.EntryAttribute{
//		&ldap.EntryAttribute{"cn", []string{"group1"}},
//		&ldap.EntryAttribute{"objectClass", []string{"groupOfNames"}},
//		&ldap.EntryAttribute{"member", []string{"uid=user1,ou=test,dc=example,dc=com"}},
//	}},
//	&ldap.Entry{"cn=group2,ou=test,dc=example,dc=com", []*ldap.EntryAttribute{
//		&ldap.EntryAttribute{"cn", []string{"group2"}},
//		&ldap.EntryAttribute{"objectClass", []string{"groupOfNames"}},
//		&ldap.EntryAttribute{"member", []string{"uid=user2,ou=test,dc=example,dc=com"}},
//	}},
//}
//
//const (
//	MockAdminDN  = "cn=admin,dc=example,dc=com"
//	MockAdminPwd = "testadmin"
//	MockBaseDN   = "ou=test,dc=example,dc=com"
//)
//
//type MockLDAPServer struct {
//}
//
//func (b MockLDAPServer) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
//	if bindDN == MockAdminDN && bindSimplePw == MockAdminPwd {
//		return ldap.LDAPResultSuccess, nil
//	}
//	//if strings.HasSuffix(bindDN, MockBaseDN) {
//	//	return ldap.LDAPResultSuccess, nil
//	//}
//	for _, user := range mockUserList {
//		if user.DN == bindDN {
//			// check password
//			for _, attr := range user.Attributes {
//				if attr.Name == "userPassword" && attr.Values[0] == bindSimplePw {
//					return ldap.LDAPResultSuccess, nil
//				}
//			}
//		}
//	}
//	return ldap.LDAPResultInvalidCredentials, nil
//}
//
//func (b MockLDAPServer) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
//	entries := []*ldap.Entry{}
//	if strings.Contains(searchReq.Filter, "objectClass=groupOfNames") {
//		if boundDN != "" {
//			for _, group := range mockGroupList {
//				if group.DN == boundDN {
//					entries = append(entries, group)
//				}
//			}
//		}
//	} else if strings.Contains(searchReq.Filter, "objectClass=inetOrgPerson") {
//		for _, user := range mockUserList {
//			if boundDN == "" {
//				for _, attri := range user.Attributes {
//					if attri.Name == "uid" && strings.Contains(searchReq.Filter, fmt.Sprintf("(uid=%s)", attri.Values[0])) {
//						entries = append(entries, user)
//					}
//				}
//			}
//			if boundDN != "" && user.DN == boundDN {
//				entries = append(entries, user)
//			}
//		}
//
//	}
//	var resultCode ldap.LDAPResultCode
//	resultCode = ldap.LDAPResultSuccess
//	if len(entries) == 0 {
//		resultCode = ldap.LDAPResultNoSuchObject
//	}
//	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, resultCode}, nil
//}
//
//func NewMockLDAPServer() *ldap.Server {
//	mockServer := ldap.NewServer()
//
//	mockServer.BindFunc("", MockLDAPServer{})
//	mockServer.SearchFunc("", MockLDAPServer{})
//
//	return mockServer
//}
