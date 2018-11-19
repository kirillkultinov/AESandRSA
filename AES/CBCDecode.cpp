#include <iostream>
#include <string>
#include <sstream>
#include <fstream>

#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/des.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"

using namespace std;
using namespace CryptoPP;
//structure for holding a block of unsigned characters
//so each block can be stored in a vector data structure
struct Block{
    unsigned char blockArr[8];
};

void des_decryption_8(unsigned char *input, unsigned char *key, unsigned char *output)
{
    DESDecryption desDecryptor;
    unsigned char xorBlock[8];
    memset(xorBlock,0,8);
    desDecryptor.SetKey(key,8);
    desDecryptor.ProcessAndXorBlock(input,xorBlock,output);
}

//main function contains all the logic of the program used to decrypt files 
//in CBC mode
// arguments are in the following order: key IV inputFile outputFile
int main(int argc, char * argv[]){

    if(argc != 5){
        cout << "program requires parameters: key IV inputFile outputFile" << endl;
        return 0;
    }

    byte key[DES::DEFAULT_KEYLENGTH];
    byte IV[DES::DEFAULT_KEYLENGTH];
    int blockLength = DES::DEFAULT_KEYLENGTH;
    //streams for reading from and writing to files
    fstream input;
    fstream output;
    
    //get bytes of the key without null termination char
    memset(key, 0, DES::DEFAULT_KEYLENGTH);
    for(int i = 0; i < DES::DEFAULT_KEYLENGTH; i++)
    {
        if(argv[1][i] != '\0')
        {
            key[i] = (byte)argv[1][i];
        }
        else{
            break;
        }
    }
    //print key
    string encodedKey;
    encodedKey.clear();
    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(encodedKey)));
    cout << "key is " << encodedKey << endl;

    //get bytes of the IV without null termination char
    memset(IV, 0, DES::DEFAULT_KEYLENGTH);
    for(int i = 0; i < DES::DEFAULT_KEYLENGTH; i++)
    {
        if(argv[2][i] != '\0')
        {
            IV[i] = (byte)argv[2][i];
        }
        else{
            break;
        }
    }
    //print IV
    string encodedIV;
    encodedIV.clear();
    StringSource(IV, sizeof(IV), true, new HexEncoder(new StringSink(encodedIV)));
    cout << "IV is " << encodedIV << endl;

    //open and read input file
    stringstream inputBuffer;
    input.open(argv[3], ios::in);
    inputBuffer << input.rdbuf();
    string cipher(inputBuffer.str());

    //get size of input file in bytes
    inputBuffer.seekg(0, ios::end);
    int inputSize = inputBuffer.tellg();
    inputBuffer.seekg(0, ios::beg);
    //cout << "cipher text: " << cipher << endl;
    cout << "size of the file is " << inputSize << " bytes"<< endl;

    //divide input into blocks of 8 bytes each
    unsigned char c = '0';
    Block block;
    vector<Block> blocks;
    //vector<Block> outputBlocks;
    int count = 0;
    while(count < inputSize){
        if(count != 0 && count % blockLength == 0){
            blocks.push_back(block);
        }
        c = inputBuffer.get();
        block.blockArr[(int)count % blockLength] = c;
        count++;
        //add the last block
        if(count == inputSize){
            blocks.push_back(block);
        }
    }
    cout << "count is " << count << endl;
    cout << "num of blocks is " << blocks.size() << endl;

    //decode blocks one by one
    string plainText = "";
    unsigned char *XORResult = new unsigned char[blockLength];
    unsigned char *decryptedBlock = new unsigned char[blockLength];
    for(int i = 0; i < blocks.size(); i++){
        //perform DES decryption on the block
        des_decryption_8(blocks[i].blockArr, key, decryptedBlock);

        //XOR output of DES with IV
        for(int j = 0; j < blockLength; j++){
            XORResult[j] = (char)(IV[j] ^ decryptedBlock[j]);
        }

        //convert plaintext block to a string
        string plainBlock(reinterpret_cast<char*>(XORResult), sizeof(XORResult));
        plainText += plainBlock;
        *IV = *blocks[i].blockArr;

    }

    //remove padding
    char lastChar = '0';
    lastChar = plainText[plainText.length() - 1];
    int numOfBytesRemove = (int)lastChar - '0';
    cout << "number of characters to remove from the padding " << numOfBytesRemove <<endl;
    plainText.erase(plainText.length() - numOfBytesRemove);
    //cout << "Plain text: " << plainText << endl;

    //write to a file
    output.open(argv[4], ios::out);
    output << plainText;

    cout << "decryption is finished! " << "decrypted file is stored in " << argv[4] <<endl;

    input.close();
    output.close();


}