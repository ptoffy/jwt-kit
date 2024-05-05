import _CryptoExtras
import Crypto
import Foundation

public protocol SPXKey: Sendable {}

public enum SPX {}

public extension SPX {
    struct PublicKey: SPXKey {
        private let backing: _CryptoExtras.SPX.PublicKey

        public init() {
            let seed: [UInt8] = (0 ..< 64).map { _ in UInt8.random(in: 0 ... 255) }
            self.backing = _CryptoExtras.SPX.PublicKey(from: seed)
        }

        public init(backing: _CryptoExtras.SPX.PublicKey) {
            self.backing = backing
        }

        public init(seed: [UInt8]) {
            self.backing = _CryptoExtras.SPX.PublicKey(from: seed)
        }

        public var bytes: [UInt8] {
            self.backing.bytes
        }

        func isValidSignature<D: Digest>(_ signature: _CryptoExtras.SPX.Signature, for digest: D) -> Bool {
            self.backing.isValidSignature(signature, for: digest)
        }
    }

    struct PrivateKey: SPXKey {
        private let backing: _CryptoExtras.SPX.PrivateKey

        public init() {
            let seed: [UInt8] = (0 ..< 64).map { _ in UInt8.random(in: 0 ... 255) }
            self.backing = _CryptoExtras.SPX.PrivateKey(from: seed)
        }

        public init(backing: _CryptoExtras.SPX.PrivateKey) {
            self.backing = backing
        }

        public init(seed: [UInt8]) {
            self.backing = _CryptoExtras.SPX.PrivateKey(from: seed)
        }

        public var bytes: [UInt8] {
            self.backing.bytes
        }

        public var publicKey: PublicKey {
            PublicKey(backing: self.backing.publicKey)
        }

        func signature<D: Digest>(for digest: D, randomized: Bool = false) -> _CryptoExtras.SPX.Signature {
            self.backing.signature(for: digest, randomized: randomized)
        }
    }
}
