import XCTest
@testable import arnot

class MockCryptoProvider: CryptoProviding {
    func generateRandomBytes() -> [UInt8] {
        let strength = 128
        let count = strength / 8
        return Array<UInt8>(repeating: 5, count: count)
    }

    func sha256(of data: [UInt8]) -> [UInt8] {
        return data
    }
}

final class BIP39Tests: XCTestCase {
    func testEntropyHasCorrectNumberOfBytes() {
        // given
        let sut = makeSUT()

        // when
        let entropy = sut.generateEntropy()

        // then
        XCTAssertEqual(entropy.count, 16)
    }

    func testEntropyHasCorrectFirstByte() {
        // given
        let sut = makeSUT()

        // when
        let entropy = sut.generateEntropy()

        // then
        XCTAssertEqual(entropy.first, 0b00000101)
    }

    func testCheckSumLengthIsFour() {
        // given
        let sut = makeSUT()

        // when
        let checksumLength = sut.checksumLength

        // then
        XCTAssertEqual(checksumLength, 4)
    }

    private func makeSUT() -> BIP39 {
        let crypto = MockCryptoProvider()
        return BIP39(crypto: crypto)
    }
}
