

#include "KeyHandler.h"



RSAKey::RSAKey()
{
    _privateKey.Initialize(_rng, BITS);
}

RSAKey::RSAKey(const char* key, unsigned int length)
{
    CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
    _privateKey.Load(ss);
}

RSAKey::RSAKey(const std::string& key)
{
    CryptoPP::StringSource ss(key, true);
    _privateKey.Load(ss);
}

RSAKey::~RSAKey()
{
}

std::string RSAKey::getPrivateKey() const
{
    std::string key;
    CryptoPP::StringSink ss(key);
    _privateKey.Save(ss);
    return key;
}

std::string RSAKey::savePrivateKey() {
    std::string privatekey = Base64::encode(getPrivateKey());
    privatekey.erase(remove(privatekey.begin(), privatekey.end(), '\n'), privatekey.end());
    std::ofstream ofs(PRIVATEKEYFILE);
    ofs << privatekey;
    return privatekey;
}

std::string RSAKey::loadPrivateKey() {
    std::ifstream ifs(PRIVATEKEYFILE);
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
}


char* RSAKey::getPrivateKey(char* keyout, unsigned int length) const
{
    CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
    _privateKey.Save(as);
    return keyout;
}

std::string RSAKey::getPublicKey() const
{
    CryptoPP::RSAFunction publicKey(_privateKey);
    std::string key;
    CryptoPP::StringSink ss(key);
    publicKey.Save(ss);
    return key;
}

char* RSAKey::getPublicKey(char* keyout, unsigned int length) const
{
    CryptoPP::RSAFunction publicKey(_privateKey);
    CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
    publicKey.Save(as);
    return keyout;
}

std::vector<uint8_t> RSAKey::decryptAesKey(const std::string& privateKeyString, const uint8_t* easEncryptedKey, size_t easEncryptedKeyLength)
{
    // Load the private RSA key
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::StringSource privateKeySource(privateKeyString, true /*pumpAll*/);
    privateKey.Load(privateKeySource);

    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);
    size_t maxPlaintextLength = rsaDecryptor.MaxPlaintextLength(easEncryptedKeyLength);
    std::vector<uint8_t> easDecryptedKey(maxPlaintextLength);
    CryptoPP::DecodingResult result = rsaDecryptor.Decrypt(rng, easEncryptedKey, easEncryptedKeyLength, easDecryptedKey.data());

    easDecryptedKey.resize(result.messageLength);
    return easDecryptedKey;
}



std::string Base64::encode(const std::string& str)
{
    std::string encoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource

    return encoded;
}

std::string Base64::decode(const std::string& str)
{
    std::string decoded;
    CryptoPP::StringSource ss(str, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)
        ) // Base64Decoder
    ); // StringSource

    return decoded;
}



std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key ){
CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

CryptoPP::AES::Encryption aesEncryption(key.data(), 16);
CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

std::vector<uint8_t> cipher;
CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::VectorSink(cipher));
stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
stfEncryptor.MessageEnd();

return cipher;
}




