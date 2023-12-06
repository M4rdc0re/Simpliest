#include <Windows.h>
#include <stdint.h>

typedef struct {
    uint16_t slice[8];
} AES_state;

typedef struct {
    AES_state rk[15];
} AES256_ctx;

typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16];
} AES256_CBC_ctx;


void AES256_CBC_init(OUT AES256_CBC_ctx* ctx, IN const unsigned char* key16, IN const uint8_t* iv);
boolean AES256_CBC_encrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* plain, IN size_t plainsize, OUT PBYTE* encrypted);
boolean AES256_CBC_decrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* encrypted, IN size_t ciphersize, OUT PBYTE* plain);