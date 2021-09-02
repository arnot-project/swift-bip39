struct BIP39 {

    let cryptoProvider: CryptoProviding
    let checksumLength = 4

    init(crypto: CryptoProviding) {
        self.cryptoProvider = crypto
    }

    func generateEntropy() -> [UInt8] {
        cryptoProvider.generateRandomBytes()
    }
}

protocol CryptoProviding {
    func generateRandomBytes() -> [UInt8]
}
