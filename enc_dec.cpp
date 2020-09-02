#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>
#include <string.h>


std::string gPublicKey = "-----BEGIN PUBLIC KEY-----\n"\
                         "MCowBQYDK2VwAyEA8rHjp5GhYuO1QS5VbDUBkfkCTEpPVQ4cIjAJ6xX++aA=\n"\
                         "-----END PUBLIC KEY-----\n"; 

std::string gPrivateKey = "-----BEGIN PRIVATE KEY-----\n"\
                          "MC4CAQAwBQYDK2VwBCIEIILUJnLB5MZjnr6wOhFOEjxQ7cjDPK2HGHxVjcs89BKT\n"\
                          "-----END PRIVATE KEY-----\n";

EVP_PKEY* createPrivateRSA(std::string aKey) {
    EVP_PKEY *lKey = nullptr;
    const char* lKeyString = aKey.c_str();
    BIO * lKeybio = BIO_new_mem_buf((void*)lKeyString, -1);
    if (nullptr == lKeybio) {
        return 0;
    }
    lKey = PEM_read_bio_PrivateKey(lKeybio, &lKey,nullptr, nullptr);
    return lKey;
}

EVP_PKEY* createPublicRSA(std::string aKey) {
    EVP_PKEY* lKey = nullptr;
    BIO *lKeybio;
    const char* lKeyString = aKey.c_str();
    lKeybio = BIO_new_mem_buf((void*)lKeyString, -1);
    if (nullptr == lKeybio) {
        return 0;
    }
    lKey = PEM_read_bio_PUBKEY(lKeybio, &lKey, nullptr, nullptr);
    return lKey;
}

unsigned char* RSASign(EVP_PKEY* aKey,
        const unsigned char* aMsg,
        size_t aMsgSize,
        size_t* aSignatureLenght) {
    EVP_MD_CTX* lCtx = EVP_MD_CTX_create();
    size_t lSignatureLenght;
    unsigned char *lSignature = nullptr;
    EVP_DigestSignInit(lCtx, nullptr, nullptr, nullptr, aKey);
    /* Calculate the requires size for the signature by passing a nullptr buffer */
    EVP_DigestSign(lCtx, nullptr, aSignatureLenght, aMsg, aMsgSize);
    lSignature = OPENSSL_zalloc(*aSignatureLenght);
    EVP_DigestSign(lCtx, lSignature, aSignatureLenght, aMsg, aMsgSize);
    EVP_MD_CTX_free(lCtx);
    return lSignature;
}

bool RSAVerifySignature(EVP_PKEY* aKey,
        unsigned char* aSignature,
        size_t aSignatureLenght,
        const unsigned char* aMsg,
        size_t aMsgSize) {
    EVP_MD_CTX* lCtx = EVP_MD_CTX_create();
    if (EVP_DigestVerifyInit(lCtx, nullptr, nullptr, nullptr, aKey)<=0) {
        return false;
    }
    if (EVP_DigestVerify(lCtx, aSignature, aSignatureLenght, aMsg, aMsgSize) <= 0) {
        return false;
    }
    return true;
}

void Base64Encode( const unsigned char* buffer,
        size_t length,
        char** base64Text) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);
    *base64Text=(*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}


char* signMessage(std::string aPrivateKey, std::string aPlainText) {
    EVP_PKEY* lPrivateRSA = createPrivateRSA(aPrivateKey); 
    size_t lSignatureLenght;
    unsigned char* lSignature = RSASign(lPrivateRSA, (unsigned char*) aPlainText.c_str(), aPlainText.length(), &lSignatureLenght);
    char* lBase64Signature;
    Base64Encode(lSignature, lSignatureLenght, &lBase64Signature);
    return lBase64Signature;
}

bool verifySignature(std::string aPublicKey, std::string aPlainText, char* aSignatureBase64) {
    EVP_PKEY* aPublicRSA = createPublicRSA(aPublicKey);
    unsigned char* lSignature;
    size_t lSignatureLenght;
    Base64Decode(aSignatureBase64, &lSignature, &lSignatureLenght);
    bool lResult = RSAVerifySignature(aPublicRSA, lSignature, lSignatureLenght, aPlainText.c_str(), aPlainText.length());
    return lResult;
}

int main() {
    std::string lText = "important message.\n";
    char* lSignature = signMessage(gPrivateKey, lText);
    bool lAuthentic = verifySignature(gPublicKey, lText, lSignature);
    if ( lAuthentic ) {
        std::cout << "Authentic" << std::endl;
    } else {
        std::cout << "Not Authentic" << std::endl;
    }
}
