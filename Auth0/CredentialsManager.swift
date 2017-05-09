// CredentialsManager.swift
//
// Copyright (c) 2017 Auth0 (http://auth0.com)
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

import Foundation
import SimpleKeychain

/// Credentials management utility
public struct CredentialsManager {

    let storage: A0SimpleKeychain
    let storeKey: String
    let authentication: Authentication

    /// Creates a new CredentialsManager instance
    ///
    /// - Parameters:
    ///   - storage: A0SimpleKeyChain instance
    ///   - authentication: Auth0 authentication instance
    ///   - storeKey: Key value used to store/retrieve the credentials object in the keychain
    public init(storage: A0SimpleKeychain, authentication: Authentication, storeKey: String) {
        self.storage = storage
        self.storeKey = storeKey
        self.authentication = authentication
    }

    /// Creates a new CredentialsManager instance with default values
    public init() {
        self.init(storage: A0SimpleKeychain(), authentication: Auth0.authentication(), storeKey: "credentials")
    }

    /// Store credentials instance in keychain
    ///
    /// - Parameter credentials: credentials instance to store
    /// - Returns: Bool outcome of success
    public func store(_ credentials: Credentials) -> Bool {
        return self.storage.setData(NSKeyedArchiver.archivedData(withRootObject: credentials), forKey: storeKey)
    }

    /// Retrieve stored credentials instance from keychain
    ///
    /// - Returns: Optional Credentials instance
    public func retrieve() -> Credentials? {
        guard let data = self.storage.data(forKey:self.storeKey) else { return nil }
        return NSKeyedUnarchiver.unarchiveObject(with: data) as? Credentials
    }

    /// Renew expired user's credentials using user's current credentials
    ///
    ///
    /// ```
    /// credentialsManager.renew(credentials) {
    ///    guard $0 == nil else { return }
    ///    let accessToken = $1?.accessToken
    /// }
    /// ```
    ///
    /// - Parameters:
    ///   - credentials: the client's existing credentials instance obtained from auth
    ///   - scope: scopes to request for the new tokens. By default is nil which will ask for the same ones requested during Auth
    ///   - callback: callback with the user's credentials or the cause of the error.
    /// - Important: This method only works for a refresh token obtained after auth with OAuth 2.0 API Authorization.
    public func renew(_ credentials: Credentials, scope: String? = nil, callback: @escaping (Error?, Credentials?) -> Void) {
        guard let refreshToken = credentials.refreshToken else {
            return callback(AuthenticationError(string: "missing refresh_token", statusCode: 0), nil)
        }
        self.authentication.renew(withRefreshToken: refreshToken, scope: scope).start {
            switch $0 {
            case .success(let credentials):
                callback(nil, credentials)
            case .failure(let error):
                callback(error, nil)
            }
        }
    }
}
