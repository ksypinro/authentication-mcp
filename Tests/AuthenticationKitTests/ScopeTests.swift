import Testing

@testable import AuthenticationKit

@Suite("Scopes")
struct ScopeTests {

    @Test("An exact scope satisfies itself")
    func exactMatch() {
        #expect(Scope.dataRead.isSatisfied(by: [.dataRead]))
        #expect(!Scope.dataWrite.isSatisfied(by: [.dataRead]))
    }

    @Test("A namespace wildcard covers every action in that namespace")
    func namespaceWildcard() {
        let granted: Set<Scope> = [Scope("data:*")]
        #expect(Scope.dataRead.isSatisfied(by: granted))
        #expect(Scope.dataWrite.isSatisfied(by: granted))
        #expect(!Scope("admin:read").isSatisfied(by: granted))
    }

    @Test("A global wildcard covers everything")
    func globalWildcard() {
        #expect(Scope("anything:at:all").isSatisfied(by: [Scope("*")]))
    }

    @Test("Scope comparison is case-sensitive, as the OAuth specs require")
    func caseSensitivity() {
        #expect(!Scope("data:read").isSatisfied(by: [Scope("DATA:READ")]))
    }

    @Test("Scope strings round-trip through the space-separated form")
    func roundTrip() {
        let scopes = Set<Scope>(scopeString: "data:write  data:read\tprofile")
        #expect(scopes == [Scope("data:read"), Scope("data:write"), Scope("profile")])
        // Serialization sorts, so the output is stable across runs.
        #expect(scopes.scopeString == "data:read data:write profile")
    }

    @Test("An empty scope string parses to an empty set")
    func emptyString() {
        #expect(Set<Scope>(scopeString: "   ").isEmpty)
    }
}
