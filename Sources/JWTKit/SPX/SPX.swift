import _CryptoExtras
import Crypto
import Foundation

public protocol SPXKey: Sendable {}

public enum SPX {}

public extension SPX {
    struct PublicKey: SPXKey {
        private let backing: _CryptoExtras.SPX.PublicKey

        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        public var derRepresentation: Data {
            backing.derRepresentation
        }

        public init(backing: _CryptoExtras.SPX.PublicKey) {
            self.backing = backing
        }

        public init(pem: String) throws {
            self.backing = try .init(pemRepresentation: pem)
        }

        public init(der: some DataProtocol) throws {
            self.backing = try .init(derRepresentation: der)
        }

        public init(seed: [UInt8]) throws {
            self.backing = try _CryptoExtras.SPX.PublicKey(from: seed)
        }

        public var bytes: [UInt8] {
            self.backing.bytes
        }

        func isValidSignature(_ signature: _CryptoExtras.SPX.Signature, for data: some DataProtocol) -> Bool {
            self.backing.isValidSignature(signature, for: data)
        }
    }

    struct PrivateKey: SPXKey {
        private let backing: _CryptoExtras.SPX.PrivateKey

        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        public var derRepresentation: Data {
            backing.derRepresentation
        }

        public init() {
            self.backing = _CryptoExtras.SPX.PrivateKey()
        }

        public init(pem: String) throws {
            self.backing = try .init(pemRepresentation: pem)
        }

        public init(der: some DataProtocol) throws {
            self.backing = try .init(derRepresentation: der)
        }

        public init(backing: _CryptoExtras.SPX.PrivateKey) {
            self.backing = backing
        }

        public init(seed: [UInt8]) throws {
            self.backing = try _CryptoExtras.SPX.PrivateKey(from: seed)
        }

        public var bytes: [UInt8] {
            self.backing.bytes
        }

        public var publicKey: PublicKey {
            PublicKey(backing: self.backing.publicKey)
        }

        func signature(for data: some DataProtocol, randomized: Bool = false) -> _CryptoExtras.SPX.Signature {
            self.backing.signature(for: data, randomized: randomized)
        }
    }
}
