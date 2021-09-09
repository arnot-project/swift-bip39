struct BIP39 {

    let cryptoProvider: CryptoProviding
    let checksumLength = 4

    init(crypto: CryptoProviding) {
        self.cryptoProvider = crypto
    }

    func generateEntropy() -> [UInt8] {
        cryptoProvider.generateRandomBytes()
    }

    func hash(of data: [UInt8]) -> [UInt8] {
        cryptoProvider.sha256(of: data)
    }

    func checksumCS(of data: [UInt8]) -> UInt8 {
        data[0] >> 4
    }

    func entropyPlusChecksumGrouped(in input: [UInt8]) -> [UInt16] {
        let left = UInt16(input.first ?? 0)
        let right = UInt16(input.last ?? 0)
        let mask: UInt16 = 0b0000011111111111
        let first: UInt16 = ((left << 3) | (right >> 5)) & mask
        let second: UInt16 = ((left << 6) | (right >> 2)) & mask
        let third: UInt16 = ((left << 9) | (right << 1) | (left >> 7)) & mask
        let fourth: UInt16 = ((left << 4) | (right >> 4)) & mask
        let fifth: UInt16 = ((left << 7) | (right >> 1)) & mask
        let sixth: UInt16 = ((left << 10) | (right << 2) | (left >> 6)) & mask

        return [
            first,
            second,
            third,
            fourth,
            fifth,
            sixth
        ]

    }
}

protocol CryptoProviding {
    func generateRandomBytes() -> [UInt8]
    func sha256(of data: [UInt8]) -> [UInt8]
}
