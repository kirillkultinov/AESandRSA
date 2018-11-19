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

void des_encryption_8(unsigned char *input, unsigned char *key, unsigned char *output)
{
	DESEncryption desEncryptor;
	unsigned char xorBlock[8];
	memset(xorBlock,0,8);
	desEncryptor.SetKey(key,8);
	desEncryptor.ProcessAndXorBlock(input,xorBlock,output); //
}

//main function contains all the logic of the program used to decrypt files 
//in CTR mode
// arguments are in the following order: key inputFile outputFile
int main(int argc, char * argv[]){

    if(argc != 4){
        cout << "program requires parameters: key inputFile outputFile" << endl;
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

    //open and read input file
    stringstream inputBuffer;
    input.open(argv[2], ios::in);
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
    unsigned char ctr[] = {'a', 'b', 'c', 'd', '1', '2', '3', '4'};
    string plainText = "";
    unsigned char *XORResult = new unsigned char[blockLength];
    unsigned char *decryptedBlock = new unsigned char[blockLength];
    for(int i = 0; i < blocks.size(); i++){

        //decrypt counter using DES and the key applying encryption algorithm
        des_encryption_8(ctr, key, decryptedBlock);

        //XOR cipher block with the result of decryption from above
        for(int j = 0; j < blockLength; j++){
            XORResult[j] = (char)(decryptedBlock[j] ^ blocks[i].blockArr[j]);
        }

        //convert plaintext block to a string
        string plainBlock(reinterpret_cast<char*>(XORResult), sizeof(XORResult));
        plainText += plainBlock;
        //increment counter
 
        for(int j = blockLength -1; j >= 0; j--){
            if(ctr[j] + 1 > 255){
                ctr[j] = 0;
            }else{
                //no carry needed, just increment the value
                ctr[j]++;
                break;
            }
        }
    }

    //remove padding
    char lastChar = '0';
    lastChar = plainText[plainText.length() - 1];
    int numOfBytesRemove = (int)lastChar - '0';
    cout << "number of characters to remove from the padding " << numOfBytesRemove <<endl;
    plainText.erase(plainText.length() - numOfBytesRemove);
    //cout << "Plain text: " << plainText << endl;

    //write to a file
    output.open(argv[3], ios::out);
    output << plainText;

    cout << "decryption is finished! " << "decrypted file is stored in " << argv[3] <<endl;

    input.close();
    output.close();


}