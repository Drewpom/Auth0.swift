// CredentialsManagerSpec.swift
//
// Copyright (c) 2016 Auth0 (http://auth0.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import Quick
import Nimble
import OHHTTPStubs
import SimpleKeychain

@testable import Auth0

private let AccessToken = UUID().uuidString.replacingOccurrences(of: "-", with: "")
private let TokenType = "bearer"
private let IdToken = UUID().uuidString.replacingOccurrences(of: "-", with: "")
private let RefreshToken = UUID().uuidString.replacingOccurrences(of: "-", with: "")
private let ExpiresIn: TimeInterval = 3600
private let ClientId = "CLIENT_ID"
private let Domain = "samples.auth0.com"

class CredentialsManagerSpec: QuickSpec {

    override func spec() {

        let authentication = Auth0.authentication(clientId: ClientId, domain: Domain)
        var credentialsManager: CredentialsManager!
        var storage: A0SimpleKeychain!
        var credentials: Credentials!

        beforeEach {
            storage = A0SimpleKeychain()
            credentialsManager = CredentialsManager(storage: storage, authentication: authentication, storeKey: "credentials")
            credentials = Credentials(accessToken: AccessToken, tokenType: TokenType, idToken: IdToken, refreshToken: RefreshToken, expiresIn: Date(timeIntervalSinceNow: ExpiresIn))
        }

        describe("storage") {

            it("should not retrieve credentials with no keychain entry") {
                expect(credentialsManager.retrieve()).to(beNil())
            }

            it("should store credentials in keychain") {
                expect(credentialsManager.store(credentials)).to(beTrue())
            }

            it("should retrieve stored credentials from keychain") {
                expect(credentialsManager.retrieve()).toNot(beNil())
                storage.clearAll()
            }

        }

        describe("renewal") {

            var error: Error?
            var newCredentials: Credentials?

            beforeEach {
                error = nil
                newCredentials = nil
                stub(condition: isToken(Domain) && hasAtLeast(["refresh_token": RefreshToken])) { _ in return authResponse(accessToken: AccessToken) }.name = "refresh_token login"
            }

            it("should error when no refresh_token present") {
                credentials = Credentials(accessToken: AccessToken, tokenType: TokenType, idToken: IdToken, refreshToken: nil, expiresIn: Date(timeIntervalSinceNow: ExpiresIn))
                credentialsManager.renew(credentials) { error = $0; newCredentials = $1 }
                expect(error).toEventuallyNot(beNil())
                expect(newCredentials).toEventually(beNil())
            }

            it("should yield new credentials") {
                waitUntil(timeout: 2) { done in
                    credentialsManager.renew(credentials) { error = $0; newCredentials = $1
                        expect(error).to(beNil())
                        expect(newCredentials?.accessToken) == AccessToken
                        done()
                    }
                }
            }
            
        }
    }
}

