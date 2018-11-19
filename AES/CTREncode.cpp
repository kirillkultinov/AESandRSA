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
    ofstream output;
    //open input file
    input.open(argv[2], ios::in);
    //open output file
    output.open(argv[3]);   
    
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
    cout << "num of blocks is " << blocks.size() << endl;



    //encode blocks one by one
    unsigned char ctr[] = {'a', 'b', 'c', 'd', '1', '2', '3', '4'}; // counter
    unsigned char *XORResult = new unsigned char[blockLength];
    unsigned char *encryptedBlock = new unsigned char[blockLength];
    for(int i = 0; i < blocks.size(); i++){

        //encrypt counter+IV block using DES and the key
        des_encryption_8(ctr, key, encryptedBlock);
        
        //XOR result and plaintext
        for(int j = 0; j < blockLength; j++){
            XORResult[j] = (char)(encryptedBlock[j] ^ blocks[i].blockArr[j]);
        }
        //write encrypted block to the file
        //need convert block to a string! Otherwise, "output << encryptedBlock" adds extra characters
        //to the file every time we write a cipher block to the file => cipher file size is bigger than plain text file
        string cipher(reinterpret_cast<char*>(XORResult), sizeof(XORResult));
        output << cipher;

        //update counter
        int carry = 0;
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

    cout << "encryption is finished! " << "encrypted file is stored in " << argv[3] <<endl;

    //close filestreams
    input.close();
    output.close();


}