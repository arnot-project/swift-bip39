struct BIP39 {

    let cryptoProvider: CryptoProviding
    let checksumLength = 4

    init(crypto: CryptoProviding) {
        self.cryptoProvider = crypto
    }

    func bip39() -> [UInt16] {
        let entropy = cryptoProvider.generateRandomBytes()
        let checkSum = checksumCS(of: cryptoProvider.sha256(of: [0]))
        return entropyPlusChecksumGrouped(
            in: entropy,
            checkSum: checkSum
        )
    }

    private func checksumCS(of data: [UInt8]) -> UInt8 {
        data[0] >> 4
    }

    private func entropyPlusChecksumGrouped(in input: [UInt8], checkSum: UInt8) -> [UInt16] {
        let mask: UInt16 = 0b0000011111111111
        let input16 = input.map { UInt16($0) }
        var output: [UInt16] = Array<UInt16>(repeating: 0, count: 12)

        for (index, value) in input16.enumerated() {
            let firstWordIndex = (index * 8) / 11
            let rightOffset = (index * 8) % 11
            output[firstWordIndex] = output[firstWordIndex] | ((value << 3) >> rightOffset)
            
            let lastWordIndex = (index * 8 + 8) / 11
            let leftOffset = 11 - (index * 8 + 8) % 11
            output[lastWordIndex] = output[lastWordIndex] | (value << leftOffset) & mask
        }

        output[11] = output[11] | UInt16(checkSum)
        return Array(output)
    }
}

protocol CryptoProviding {
    func generateRandomBytes() -> [UInt8]
    func sha256(of data: [UInt8]) -> [UInt8]
}
