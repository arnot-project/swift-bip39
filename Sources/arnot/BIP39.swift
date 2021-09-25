enum EntropyLength {
    case bits128, bits160, bits192, bits224, bits256

    var size: Int {
        switch self {
            case .bits128: return 128
            case .bits160: return 160
            case .bits192: return 192
            case .bits224: return 224
            case .bits256: return 256
        }
    }
}

protocol CryptoProviding {
    func generateRandomBytes(withSize size: Int) -> [UInt8]
    func sha256(of data: [UInt8]) -> [UInt8]
}

struct BIP39 {

    let cryptoProvider: CryptoProviding
    let checksumLength = 4

    init(crypto: CryptoProviding) {
        self.cryptoProvider = crypto
    }

    func bip39(withENT ent: EntropyLength) -> [UInt16] {
        let entropy = cryptoProvider.generateRandomBytes(withSize: ent.size)
        let sha = cryptoProvider.sha256(of: entropy)
        let checkSum = sha[0] >> (8 - ((entropy.count * 8) / 32))
        return entropyPlusChecksumGrouped(
            in: entropy,
            checkSum: checkSum
        )
    }

    private func entropyPlusChecksumGrouped(in input: [UInt8], checkSum: UInt8) -> [UInt16] {
        let mask: UInt16 = 0b0000011111111111
        let input16 = input.map { UInt16($0) }
        let count = (input.count * 8 + (input.count * 8 / 32)) / 11
        var output: [UInt16] = Array<UInt16>(repeating: 0, count: count)

        for (index, value) in input16.enumerated() {
            let firstWordIndex = (index * 8) / 11
            let rightOffset = (index * 8) % 11
            output[firstWordIndex] = output[firstWordIndex] | ((value << 3) >> rightOffset)
            
            let lastWordIndex = (index * 8 + 8) / 11
            let leftOffset = 11 - (index * 8 + 8) % 11
            output[lastWordIndex] = output[lastWordIndex] | (value << leftOffset) & mask
        }

        output[count - 1] = output[count - 1] | UInt16(checkSum)
        return Array(output)
    }
}
