#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "all.h"

//   ./main <nom du fichier .bmp> <chiffrement | dechiffrement> <1 | 2 | 3>(128 | 192 | 256) <0 | 1>(ECB | CBC)
void main (int argc , char* argv[]) {
    


    if (argc != 5)



	{
        //TESTS
        //test_subBytes();
        //test_shiftRows();
        //test_keyExpanssion();
        //test_mixed_column();
        //test_inv_mixed_column();
        //test_encrypt_128();
        //test_encrypt_192();
        //test_encrypt_256();
        //test_encrypt_CBC_128();
        //test_encrypt_CBC_192();
        //test_encrypt_CBC_256();
        //tests_file_encrypt_128();
        //tests_file_encrypt_192();
        //tests_file_encrypt_256();
    }

    else

    {
        int taille;
        
        switch (argv[3][0])
        {
        case '1': taille = 128;
        case '2': taille = 192;
        case '3': taille = 256;
        default : taille = 128;
        }
        

        int mode;
        if (argv[4][0]=='0') mode = 0;
        else mode = 1;
    
    
        //Chiffrement ou dechiffrement de l'image
        
        if (argv[2][0]=='c') file_encrypt(argv[1], encryption_key(taille), mode, taille);
        if (argv[2][0]=='d') file_decrypt(argv[1], encryption_key(taille), mode, taille);
    }
    

}