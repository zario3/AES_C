#include <stdio.h>
#include <stdint.h>
#include "all.h"

//Des examples pour les testes
STATE state_ex = {0x32,0x43,0xF6,0xA8,0x88,0x5A,0x30,0x8D,0x31,0x31,0x98,0xA2,0xE0,0x37,0x07,0x34};
STATE state_ex1 = {0xD4,0xBF,0x5D,0x30,0xE0,0xB4,0x52,0xAE,0xB8,0x41,0x11,0xF1,0x1E,0x27,0x98,0xE5}; //Utilisé dans le test de Mix Column
STATE text = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}; //Le message à chiffrer
char data_ex[32] = {0x32,0x43,0xF6,0xA8,0x88,0x5A,0x30,0x8D,0x31,0x31,0x98,0xA2,0xE0,0x37,0x07,0x34,0x32,0x43,0xF6,0xA8,0x88,0x5A,0x30,0x8D,0x31,0x31,0x98,0xA2,0xE0,0x37,0x07,0x34};
char data_ex1[32] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
uint8_t cipher_key128_ex[16] = {0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C};
uint8_t cipher_key192_ex[24] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
uint8_t cipher_key256_ex[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};

//Fontion de test pour la fonction subBytes
void test_subBytes()
{   printf("Test de subBytes :\n");
    print_state(state_ex);
    SubBytes(state_ex);
    print_state(state_ex);
    invSubBytes(state_ex);
    print_state(state_ex);
}

//Fonction de test pour la fonction shiftRows
void test_shiftRows()
{   printf("Test de shifRows :\n");
	print_state(state_ex);
	ShiftRows(state_ex);
	print_state(state_ex);
	invShiftRows(state_ex);
	print_state(state_ex);
}

//Fonction de test pour la fonction key_expanssion
void test_keyExpanssion()
{
    //Pour une clé de 128 bits, la clé cipher_key128_ex est définie dans aes.h
    printf("Test de key_Expanssion pour une clé de 128 bits :\n");
    uint32_t word[44];
	key_expanssion(cipher_key128_ex, word, 4);
	STATE keySet[11];	
	word2key (word, keySet, 11);
	for (int i = 0; i < 11; i++)
	{
		print_state(keySet[i]);
	}

    //Pour une clé de 192 clé, la clé cipher_key192_ex est définie dans aes.h
    printf("Test de key_Expanssion pour une clé de 192 bits :\n");
    uint32_t word1[56];
	key_expanssion(cipher_key192_ex, word1, 6);
	STATE keySet1[13];	
	word2key (word1, keySet1, 13);
	for (int i = 0; i < 13; i++)
	{
		print_state(keySet1[i]);
	}

    //Pour une clé de 256 clé, la clé cipher_key256_ex est définie dans aes.h
    printf("Test de key_Expanssion pour une clé de 256 bits :\n");
    uint32_t word2[68];
	key_expanssion(cipher_key256_ex, word2, 8);
	STATE keySet2[15];	
	word2key (word2, keySet2, 15);
	for (int i = 0; i < 15; i++)
	{
		print_state(keySet2[i]);
	}
}

//Fonction de test de Mixed Column
void test_mixed_column()
{
    printf("Test de Mixed Column :\n");
    print_state(state_ex1);
    mixed_column(state_ex1);
    print_state(state_ex1);
}

//Fonction de test inverse de Mixed Column
void test_inv_mixed_column()
{
    printf("Test de inv Mixed Column :\n");
    print_state(state_ex1);
    inv_mixed_column(state_ex1);
    print_state(state_ex1);
}

//Fonction de test pour la fonction qui chiffre et déchiffre en mode ECB pour une taille de 128bits
void test_encrypt_128()
{   printf("Test de chiffrement ECB pour le 128 :\n");
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex[i]);
    printf(" ");
    }
    printf("\n");
    aes_encrypt(data_ex, 32, cipher_key128_ex, 128);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex[i]);
    printf(" ");
    }
    printf("\n");
    aes_decrypt(data_ex, 32, cipher_key128_ex, 128);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex[i]);
    printf(" ");
    }
    printf("\n");
}

//Fonction de test pour la fonction qui chiffre et déchiffre en mode ECB pour une taille de 192bits
void test_encrypt_192()
{   printf("Test de chiffrement ECB pour le 192 :\n");
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_encrypt(data_ex1, 32, cipher_key192_ex, 192);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_decrypt(data_ex1, 32, cipher_key192_ex, 192);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
}

//Fonction de test pour la fonction qui chiffre et déchiffre en mode ECB pour une taille de 256bits
void test_encrypt_256()
{   printf("Test de chiffrement ECB pour le 256 :\n");
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_encrypt(data_ex1, 32, cipher_key256_ex, 256);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_decrypt(data_ex1, 32, cipher_key256_ex, 256);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
}

//Fonction de test pour la fonction qui chiffre et déchiffre en mode CBC pour une taille de 128bits
void test_encrypt_CBC_128()
{   printf("Test de chiffrement CBC pour le 128 :\n");
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex[i]);
    printf(" ");
    }
    printf("\n");
    aes_encrypt_CBC(data_ex, 32, cipher_key128_ex, 128);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex[i]);
    printf(" ");
    }
    printf("\n");
    aes_decrypt_CBC(data_ex, 32, cipher_key128_ex, 128);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex[i]);
    printf(" ");
    }
    printf("\n");
}

//Fonction de test pour la fonction qui chiffre et déchiffre en mode CBC pour une taille de 192bits
void test_encrypt_CBC_192()
{   printf("Test de chiffrement CBC pour le 192 :\n");
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_encrypt_CBC(data_ex1, 32, cipher_key192_ex, 192);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_decrypt_CBC(data_ex1, 32, cipher_key192_ex, 192);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
}
//Fonction de test pour la fonction qui chiffre et déchiffre en mode CBC pour une taille de 256bits
void test_encrypt_CBC_256()
{   printf("Test de chiffrement CBC pour le 256 :\n");
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_encrypt_CBC(data_ex1, 32, cipher_key256_ex, 256);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
    aes_decrypt_CBC(data_ex1, 32, cipher_key256_ex, 256);
    for (int i=0; i<32; i++){
    printf("%02x", (uint8_t)data_ex1[i]);
    printf(" ");
    }
    printf("\n");
}

//Fonction de test qui chiffre et déchiffre un fichier bitmap en mode ECB et CBC pour le 128bits
void tests_file_encrypt_128()
{   
    //
    //file_encrypt("test.bmp", cipher_key256_ex, 0, 128);
    //file_decrypt("test.bmp", cipher_key256_ex, 0, 128);
    //file_encrypt("test.bmp", cipher_key256_ex, 1, 128);
    //file_decrypt("test.bmp", cipher_key256_ex, 1, 128);
}

//Fonction de test qui chiffre et déchiffre un fichier bitmap en mode ECB et CBC pour le 192bits
void tests_file_encrypt_192()
{
    /*file_encrypt("test.bmp", cipher_key256_ex, 0, 192);
    file_decrypt("test.bmp", cipher_key256_ex, 0, 192);
    file_encrypt("test.bmp", cipher_key256_ex, 1, 192);
    file_decrypt("test.bmp", cipher_key256_ex, 1, 192);*/
}

//Fonction de test qui chiffre et déchiffre un fichier bitmap en mode ECB et CBC pour le 256bits
void tests_file_encrypt_256()
{
    //file_encrypt("test.bmp", cipher_key256_ex, 0, 256);
    //file_decrypt("test.bmp", cipher_key256_ex, 0, 256);
    //file_encrypt("test.bmp", cipher_key256_ex, 1, 256);
    //file_decrypt("test.bmp", cipher_key256_ex, 1, 256);
}

char* encryption_key(int sizekey)
{
    switch (sizekey)
    {
        case 128: return cipher_key128_ex;
        case 192: return cipher_key192_ex;   
        case 256: return cipher_key256_ex;
    }
}