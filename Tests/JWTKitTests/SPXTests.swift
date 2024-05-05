import _CryptoExtras
import JWTKit
import XCTest

final class SPXTests: XCTestCase {
    func testSPXSigner() async throws {
        let seed: [UInt8] = (0 ..< 64).map { _ in UInt8.random(in: 0 ... 255) }
        let privateKey = SPX.PrivateKey(seed: seed)
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
}
