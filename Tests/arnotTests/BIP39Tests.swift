import XCTest
@testable import arnot

class MockCryptoProvider: CryptoProviding {
    func generateRandomBytes() -> [UInt8] {
        let strength = 128
        let count = strength / 8
        return Array<UInt8>(repeating: 5, count: count)
    }

    func sha256(of data: [UInt8]) -> [UInt8] {
        return [249]
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

    func testSha256() {
        // given
        let sut = makeSUT()

        // when
        let hash = sut.hash(of: sut.generateEntropy())

        // then
        XCTAssertEqual(hash.first, 0b11111001)
    }

    func testCaclucalteChecksumCS() {
        // given
        let sut = makeSUT()

        // when
        let checksumCS = sut.checksumCS(of: sut.hash(of: sut.generateEntropy()))

        // then
        XCTAssertEqual(checksumCS, 0b1111)
    }

    func testEntropyPlusChecksumGrouped() {
        // given
        let sut = makeSUT()

        // when
        let input = Array<UInt8>(repeating: 1, count: 16)
        let groups = sut.entropyPlusChecksumGrouped(in: input)

        // then
        XCTAssertEqual(groups.first, 0b0000000000001000)
    }

    func testEntropy129PlusChecksumGrouped() {
        // given
        let sut = makeSUT()

        // when
        let input = Array<UInt8>(repeating: 129, count: 16)
        let groups = sut.entropyPlusChecksumGrouped(in: input)

        // then
        XCTAssertEqual(groups.first, 0b0000010000001100)
    }


    func testEntropyPlusChecksumGroupedWithArguments() {
        // given
        let sut = makeSUT()
        let input = Array<UInt8>(repeating: 0, count: 16)

        // when
        let groups = sut.entropyPlusChecksumGrouped(in: input)

        // then
        XCTAssertEqual(groups.first, 0b0000000000000000)
    }

    private func makeSUT() -> BIP39 {
        let crypto = MockCryptoProvider()
        return BIP39(crypto: crypto)
    }
}
