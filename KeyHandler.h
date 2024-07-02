#pragma once
#ifndef KEYHANDLER_H
#define KEYHANDLER_H

#include <iostream>
#include <string>

#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <filters.h>
#include <files.h>

#include <eax.h>
#include <sha.h>



////////////////////////////
/////////defines////////////
///////////////////////////

#define RSABITSIZE 1024
#define RSASIZE 160
#define PRIVATEKEYFILE "priv.key"


class RSAKey
{
public:
	static const unsigned int BITS = RSABITSIZE;

private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;

	RSAKey(const RSAKey& rsaprivate);
	RSAKey& operator=(const RSAKey& rsaprivate);
public:
	RSAKey();
	RSAKey(const char* key, unsigned int length);
	RSAKey(const std::string& key);
	~RSAKey();


	std::string savePrivateKey();
	static std::string loadPrivateKey();
	std::string getPrivateKey() const;
	char* getPrivateKey(char* keyout, unsigned int length) const;

	std::string getPublicKey() const;
	char* getPublicKey(char* keyout, unsigned int length) const;

	static std::vector<uint8_t> decryptAesKey(const std::string&, const uint8_t*, size_t);
};

class Base64
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};



std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>&, const std::vector<uint8_t>&);




#endif /* KEY_HANDLER */