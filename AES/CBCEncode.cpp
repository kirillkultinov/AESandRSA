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
	desEncryptor.ProcessAndXorBlock(input,xorBlock,output); 
}

//main function contains all the logic of the program used to encrypt files 
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
    ofstream output;
    //open input file
    input.open(argv[3], ios::in);
    //open output file
    output.open(argv[4]);   
    
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

    //read input file
    stringstream inputBuffer;
    inputBuffer << input.rdbuf();
    string plain(inputBuffer.str());

    //get size of input file in bytes
    inputBuffer.seekg(0, ios::end);
    int inputSize = inputBuffer.tellg();
    inputBuffer.seekg(0, ios::beg);
    //cout << "plain text: " << plain << endl;
    cout << "size of the file before padding is " << inputSize << " bytes"<< endl;

    //append padding bytes 
    int paddingBytes[9] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int charsToAppend = 8 - (inputSize % blockLength);
    cout << "need to append " << charsToAppend << " bytes" << endl;
    for(int i = 0; i < charsToAppend; i++){
        inputBuffer << std::hex << paddingBytes[charsToAppend];
    }
    inputBuffer.seekg(0, ios::end);
    inputSize = inputBuffer.tellg();
    inputBuffer.seekg(0, ios::beg);
    cout << "size of the file after padding is " << inputSize << " bytes"<< endl;

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

    //encode blocks one by one
    unsigned char *XORResult = new unsigned char[blockLength];
    unsigned char *encryptedBlock = new unsigned char[blockLength];
    for(int i = 0; i < blocks.size(); i++){
        //XOR plaintext block and IV
        for(int j = 0; j < blockLength; j++){
            XORResult[j] = (char)(IV[j] ^ blocks[i].blockArr[j]);
        }
        //perform DES encryption on the block
        des_encryption_8(XORResult, key, encryptedBlock);

        //write encrypted block to a file
        //need convert block to a string! Otherwise, "output << encryptedBlock" adds extra characters
        //to the file every time we write a cipher block to the file => cipher file size is bigger than plain text file
        string cipher(reinterpret_cast<char*>(encryptedBlock), sizeof(encryptedBlock));
        output << cipher;
        //cout << "pushed ciher block size is " << sizeof(encryptedBlock) << endl;
        //update the IV
        *IV = *encryptedBlock;
    }

    cout << "encryption is finished! " << "encrypted file is stored in " << argv[4] <<endl;

    //close filestreams
    input.close();
    output.close();


}