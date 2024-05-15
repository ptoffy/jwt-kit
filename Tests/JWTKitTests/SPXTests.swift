import JWTKit
import XCTest

final class SPXTests: XCTestCase {
    func testSPXSigner() async throws {
        let privateKey = SPX.PrivateKey()
        let keyCollection = await JWTKeyCollection().addSPX(key: privateKey)

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let privateSigned = try await keyCollection.sign(payload)
        try await XCTAssertEqualAsync(await keyCollection.verify(privateSigned, as: TestPayload.self), payload)
    }

    func testSPXPEM() async throws {
        let privateKey = try SPX.PrivateKey(pem: spx128sPrivateKey)

        let keyCollection = await JWTKeyCollection()
            .addSPX(key: privateKey, kid: "private")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let privateSigned = try await keyCollection.sign(payload)
        try await XCTAssertEqualAsync(await keyCollection.verify(privateSigned, as: TestPayload.self), payload)
    }

    let spx128sPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    Jyl8Ef+FbvH9voZx/Y0kM+VNs3SNYw/PqLX47eN5haokJW+Qx/7+5KAevFwGhDGR
    Q8DmXAf+gNKuOxQHmEOcMg==
    -----END PRIVATE KEY-----
    """

    let spx128sPublicKey = """
    -----BEGIN PUBLIC KEY-----
    JCVvkMf+/uSgHrxcBoQxkUPA5lwH/oDSrjsUB5hDnDI=
    -----END PUBLIC KEY-----
    """
}
