#include "tests.h"

//Definition de type
typedef uint8_t STATE[16];

//les fonctions des fichiers aes.c & encrypt.c
void print_state(STATE state);
void SubBytes(STATE state);
void invSubBytes(STATE state);
void ShiftRows(STATE state);
void invShiftRows(STATE state);
unsigned int Rot(uint32_t key);
unsigned int SubByteWord(uint32_t word);
void addRoundKey(STATE s, STATE key);
uint32_t byte2word(uint8_t byte[]);
void key_expanssion(unsigned char key[], unsigned int word[], char Nk);
void word2key(uint32_t word[], STATE keys[], uint8_t Nk);
uint8_t mult_byte(uint8_t a, uint8_t b);
void mixed_column(STATE s);
void inv_mixed_column(STATE s);
void cipher(STATE state, STATE keySet[], uint8_t Nk);
void inv_cipher(STATE state, STATE keySet[], uint8_t Nk);
int aes_encrypt(char* data, int size, char* key, int keysize);
int aes_decrypt(char* data, int size, char* key, int keysize);
int aes_encrypt_CBC(char* data, int size, char* key, int keysize);
int aes_decrypt_CBC(char* data, int size, char* key, int keysize);
FILE* open_file(const char *name, const char *mode);
void close_file(const char *name, FILE *fichier);
void file_encrypt(char* name, char* key, int mode, int keysize);
void file_decrypt(char* name, char* key, int mode, int keysize);