#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "all.h"


//Fonction de chiffrement en mode ECB d'une chaine de caractères.
//Si la taille de l'entrée n'est pas multiple de 16 octets les dernières octets resteront sans chiffrer
int aes_encrypt(char* data, int size, char* key, int keysize)
{
    int Nk = keysize/32;
    //Initialiser le word qui contient tout les clefs
    uint32_t* word = malloc(4*(Nk+7)*sizeof(uint32_t));
    //Vérification 
    if (word == NULL) return 1;
	key_expanssion((uint8_t*)key, word, Nk);

	//Initialiser la liste des clefs
    STATE* keySet = malloc((Nk+7)*sizeof(STATE));
    //Vérification 
    if (keySet == NULL) return 1;
	word2key(word, keySet, (Nk+7));
    free(word);

    //Chiffrement du data
    uint8_t* p = (uint8_t*) data;
    for (int i=0; i < size; i+=16){
        cipher(p+i, keySet, Nk);
    }
    free(keySet);
    return 0;
}


//Fonction de dechiffrement en mode ECB d'une chaine de caractères chiffrée
int aes_decrypt(char* data, int size, char* key, int keysize)
{
    int Nk = keysize/32;
    //Initialiser le word qui contient tout les clefs
    uint32_t* word = malloc(4*(Nk+7)*sizeof(uint32_t));
    //Vérification 
    if (word == NULL) return 1;
	key_expanssion((uint8_t*)key, word, Nk);

	//Initialiser la liste des clefs
    STATE* keySet = malloc((Nk+7)*sizeof(STATE));
    //Vérification 
    if (keySet == NULL) return 1;
	word2key(word, keySet, (Nk+7));
    free(word);

    //Chiffrement du data
    uint8_t* p = (uint8_t*) data;
    for (int i=0; i < size; i+=16){
        inv_cipher(p+i, keySet, Nk);
    }
    free(keySet);
    return 0;
}

//Fonction de chiffrement en mode CBC
int aes_encrypt_CBC(char* data, int size, char* key, int keysize)
{
    int Nk = keysize/32;
    //Initialiser le word qui contient tout les clefs
    uint32_t* word = malloc(4*(Nk+7)*sizeof(uint32_t));
    //Vérification 
    if (word == NULL) return 1;
	key_expanssion((uint8_t*)key, word, Nk);

	//Initialiser la liste des clefs
    STATE* keySet = malloc((Nk+7)*sizeof(STATE));
    //Vérification 
    if (keySet == NULL) return 1;
	word2key(word, keySet, (Nk+7));
    free(word);

    //Chiffrement du data
    uint8_t* p = (uint8_t*) data;
    cipher(p, keySet, Nk);
    for (int i=16; i < size; i+=16){
        addRoundKey(p+i, p+i-16);
        cipher(p+i, keySet, Nk);
    }
    free(keySet);
    return 0;
}

//Fonction de dechiffrement de mode CBC
int aes_decrypt_CBC(char* data, int size, char* key, int keysize)
{
    int Nk = keysize/32;
    //Initialiser le word qui contient tout les clefs
    uint32_t* word = malloc(4*(Nk+7)*sizeof(uint32_t));
    //Vérification 
    if (word == NULL) return 1;
	key_expanssion((uint8_t*)key, word, Nk);

	//Initialiser la liste des clefs
    STATE* keySet = malloc((Nk+7)*sizeof(STATE));
    //Vérification 
    if (keySet == NULL) return 1;
	word2key(word, keySet, (Nk+7));
    free(word);

    //Chiffrement du data
    uint8_t* p = (uint8_t*) data;
    uint8_t temp[size];
    for (int i = 0 ; i<size ; i++) temp[i]=data[i];
    inv_cipher(p, keySet, Nk);
    for (int i = 16; i < size; i += 16) {
        inv_cipher(p + i, keySet, Nk);
        addRoundKey(p + i, temp+i-16);
    }
    free(keySet);
    return 0;
}

//Cette fonction ouvre un fichier et vérifie qu'il n'y a pas eu de problème
FILE* open_file(const char *name, const char *mode)
{
    FILE* fichier = fopen(name, mode);
    if (fichier == NULL){
        fprintf(stderr,"Erreur ouverture %s", name);
        perror("");
        fprintf(stderr,"Impossible de continuer !!\n");
        exit (EXIT_FAILURE);
    }
    return fichier;
}

//Cette fonction ferme un fichier et vérifie qu'il n'y a pas eu de problème
void close_file(const char *name, FILE *fichier)
{
    if (fclose(fichier) == EOF){
        fprintf(stderr,"Erreur fermeture %s", name);
        exit (EXIT_FAILURE);
    }
}

//Cette fonction chiffre une image en format bitmap
void file_encrypt(char* name, char* key, int mode, int keysize)
{
    FILE *fichier = open_file(name,"rb+");
    int offset;
    fseek(fichier, 10, SEEK_SET);
    fread(&offset, 4, 1, fichier);
    int taille;
    fseek(fichier, 2, SEEK_SET);
    fread(&taille, 4, 1, fichier);
    taille -= offset;
    fseek(fichier, offset, SEEK_SET);
    char* temp = malloc(taille*sizeof(char));
    fread(temp, taille, 1, fichier);

    if (mode == 1) aes_encrypt_CBC(temp, taille, key, keysize);
    else aes_encrypt(temp, taille, key, keysize);

    fseek(fichier, offset, SEEK_SET);
    fwrite(temp, taille, 1, fichier);
    close_file(name, fichier);
    free(temp);
}

//Fonction de dechiffrement d'une image en format bitmap.
void file_decrypt(char* name, char* key, int mode, int keysize)
{
    int Nk = keysize/32;
    FILE *fichier = open_file(name,"rb+");
    int offset;
    fseek(fichier, 10, SEEK_SET);
    fread(&offset, 4, 1, fichier);
    int taille;
    fseek(fichier, 2, SEEK_SET);
    fread(&taille, 4, 1, fichier);
    taille -= offset;
    fseek(fichier, offset, SEEK_SET);
    char* temp = malloc(taille*sizeof(char));
    fread(temp, taille, 1, fichier);

    if (mode == 1) aes_decrypt_CBC(temp, taille, key, keysize);
    else aes_decrypt(temp, taille, key, keysize);

    fseek(fichier, offset, SEEK_SET);
    fwrite(temp, taille, 1, fichier);
    close_file(name, fichier);
    free(temp);
}