import XCTest
@testable import arnot

struct MockCryptoProvider: CryptoProviding {
    let entropy: [UInt8]
    let sha256: [UInt8]

    func generateRandomBytes(withSize size: Int) -> [UInt8] {
        assert(size == entropy.count * 8)
        return entropy
    }

    func sha256(of data: [UInt8]) -> [UInt8] {
        assert(data == entropy)
        return sha256
    }
}

final class BIP39Tests: XCTestCase {

    //1:  xxx xxxx xyyy
    //2:  yyy yyzz zzzz
    //3:  zza aaaa aaab
    //4:  bbb bbbb cccc
    //5:  ccc cddd dddd
    //6:  dee eeee eeff
    //7:  fff fffg gggg
    //8:  ggg hhhh hhhh
    //9:  xxx xxxx xyyy
    //10: yyy yyzz zzzz
    //11: zza aaaa aaab
    //12: bbb bbbb cccc
    func testVerifyArrayOf1sWithChecksumZero() {
        // given
        let sut = makeSUT(entropy: Array<UInt8>(repeating: 1, count: 128 / 8), sha256: [16])
        let expectedArray: [UInt16] = [
            0b0000_0000_0000_1000,
            0b0000_0000_0100_0000,
            0b0000_0010_0000_0010,
            0b0000_0000_0001_0000,
            0b0000_0000_1000_0000,
            0b0000_0100_0000_0100,
            0b0000_0000_0010_0000,
            0b0000_0001_0000_0001,
            0b0000_0000_0000_1000,
            0b0000_0000_0100_0000,
            0b0000_0010_0000_0010,
            0b0000_0000_0001_0001
        ]

        // when
        let groups = sut.bip39(withENT: .bits128)

        // then
        XCTAssertEqual(groups, expectedArray)
    }

    func testVerifyArrayOf129sWithChecksumZero() {
        // given
        let sut = makeSUT(entropy: Array<UInt8>(repeating: 129, count: 128 / 8), sha256: [128])
        let expectedArray: [UInt16] = [
            0b0000_0100_0000_1100,
            0b0000_0000_0110_0000,
            0b0000_0011_0000_0011,
            0b0000_0000_0001_1000,
            0b0000_0000_1100_0000,
            0b0000_0110_0000_0110,
            0b0000_0000_0011_0000,
            0b0000_0001_1000_0001,
            0b0000_0100_0000_1100,
            0b0000_0000_0110_0000,
            0b0000_0011_0000_0011,
            0b0000_0000_0001_1000
        ]

        // when
        let result = sut.bip39(withENT: .bits128)

        // then
        XCTAssertEqual(result, expectedArray)
    }

    func testStrength256() {
        // given
        let sut = makeSUT(entropy: Array<UInt8>(repeating: 129, count: 256 / 8), sha256: [128])
        let expectedArray: [UInt16] = [
            0b0000_0100_0000_1100,
            0b0000_0000_0110_0000,
            0b0000_0011_0000_0011,
            0b0000_0000_0001_1000,
            0b0000_0000_1100_0000,
            0b0000_0110_0000_0110,
            0b0000_0000_0011_0000,
            0b0000_0001_1000_0001,
            0b0000_0100_0000_1100,
            0b0000_0000_0110_0000,
            0b0000_0011_0000_0011,
            0b0000_0000_0001_1000,
            0b0000_0000_1100_0000,
            0b0000_0110_0000_0110,
            0b0000_0000_0011_0000,
            0b0000_0001_1000_0001,
            0b0000_0100_0000_1100,
            0b0000_0000_0110_0000,
            0b0000_0011_0000_0011,
            0b0000_0000_0001_1000,
            0b0000_0000_1100_0000,
            0b0000_0110_0000_0110,
            0b0000_0000_0011_0000,
            0b0000_0001_1000_0000
        ]

        // when
        let result = sut.bip39(withENT: .bits256)

        // then
        XCTAssertEqual(result, expectedArray)
    }

    private func makeSUT(
        entropy: [UInt8] = Array<UInt8>(repeating: 5, count: 128 / 8),
        sha256: [UInt8] = [249]
    ) -> BIP39 {
        BIP39(crypto: MockCryptoProvider(
            entropy: entropy,
            sha256: sha256))
    }
}

