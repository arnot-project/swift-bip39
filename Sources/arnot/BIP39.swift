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

        return [(left << 3) | (right >> 5)]
    }
}

protocol CryptoProviding {
    func generateRandomBytes() -> [UInt8]
    func sha256(of data: [UInt8]) -> [UInt8]
}
