import _CryptoExtras

public extension JWTKeyCollection {
    @discardableResult
    func add(
        key: some SPXKey,
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        add(.init(
            algorithm: SPXSigner(key: key, algorithm: .sha256, name: "SPHINCS+128s"),
            parser: parser,
            serializer: serializer
        ),
        for: kid)
    }
}
