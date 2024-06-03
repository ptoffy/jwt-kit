import _CryptoExtras
import Foundation

struct SPXSigner: JWTAlgorithm, CryptoSigner {
    let publicKey: SPX.PublicKey
    let privateKey: SPX.PrivateKey?
    var algorithm: DigestAlgorithm
    let name: String

    init(key: some SPXKey, algorithm: DigestAlgorithm, name: String) {
        switch key {
        case let key as SPX.PrivateKey:
            self.privateKey = key
            self.publicKey = key.publicKey
        case let key as SPX.PublicKey:
            self.publicKey = key
            self.privateKey = nil
        default:
            // This should never happen
            fatalError("Unexpected key type: \(type(of: key))")
        }
        self.algorithm = algorithm
        self.name = name
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        guard let privateKey else {
            throw JWTError.signingAlgorithmFailure(SPXError.privateKeyOrSeedRequired)
        }

        let signature = privateKey.signature(for: plaintext)
        return [UInt8](signature.rawRepresentation)
    }

    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        let signature = _CryptoExtras.SPX.Signature(rawRepresentation: signature)

        return publicKey.isValidSignature(signature, for: plaintext)
    }
}
