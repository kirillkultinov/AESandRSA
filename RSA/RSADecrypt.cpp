#include "cryptopp/cryptlib.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>

using namespace CryptoPP;
using namespace std;

int main(int argc, char * argv[]){

    cout << "RSA Decryption!" << endl;
    //setting up public key
    Integer modulusValue("0x2bf2978bc6d37fbfccdb013f2c33cac70bf704103aa8e8c39872e53df3812096228af96585d7cd4c036e36112a5f7c52b0b18c984e595894edb507c74cc1f0e1242016858be4f31c094d7904cf24c784d1976ec8cb95fd7adf3f331cda949fe1c903224ffd7dcc538467296996abad0d63338652ca08650e1d1490ab5fc482277af187ab83e9ebcf8108e0216a2cc4aff41b0458545868d5c9d210a0a1337e6f221ed5dfbfab2547dc6a80f35f78969c07208325cc106d583c6869555ada27026d5fa118ab8c3ef34209906d6de2af61b955f3baf41059b5e0daf9d6b38dcaff5aeb6baddca656208435b9e78385305645ce2b440fd5eb3b9e70b890dd32f8d");
    Integer pubExponent("0x132f6ca389a263b32cf4354714c61878840bb20b4951fe9b5e24900633be5f60139d738b9a55ef20ff4c4380f7e37e5fc323c0fe78fb22ebcb8c055fe747b29df041a324796fe2850a927460220ab6917d2080e8cf20f1616df41edeebee8089e2346d5be902f957e618e18b0a4904fa0eaf839485605dda9e05a80d000bc3278f557eb65a465961e2469436b5d7166a6f155fa7104626c309f297369af482735463e36d7e4715a874f8fa6d3aba95dbeabc5773546957e9797247c35533bca3cec62934b875cc8ac11b294dbe6a147602e18ff39a01bcfe1187c0095d49a3cfa52d500381eda217595b8c70cc8b2a46a477f2bec557703dc7441301a748e3");
    Integer privExponent("0x1f7bcdec632aeb6c4aa0d6a34dbd622743376f8eb80a71b5c137729aa4a0c45f482acb2066e93079bf15bb399cf7968f1e9ce9cf079ba43a8d9a8a38665075ce762e0bd3ec55d37aeb5ece0b0ebdcde5b9f971471e76f2facd074dde8b7036a277195da2d6bb9d1e3c75d404c08d7bf90db6585f76688160c7efe9cd94c059771bbb7a1e548001370bd474bacd11aa97c92936e9b2f9875131ebdaa7c17868ffb50bfe745058f015b4ea15fc0285a04e3fb473468f4d1dab790737aa26e00a76a1f4df4f07c7fdf13d7f031082d9bf7688423a6f83502a8c076cab00002efe9d9ae252703cbed2bff3e7ad557e0743792cbea6be7ded30aef8e40d3c275422b");

    RSA::PrivateKey privKey;
    privKey.Initialize(modulusValue, pubExponent, privExponent);

    //streams for reading from and writing to files
    fstream input;
    ofstream output;
    //open input file
    input.open(argv[1], ios::in);
    //open output file
    output.open(argv[2]); 

    //read input file
    stringstream inputBuffer;
    inputBuffer << input.rdbuf();
    string plain(inputBuffer.str());

    //get size of input file in bytes
    inputBuffer.seekg(0, ios::end);
    int inputSize = inputBuffer.tellg();
    inputBuffer.seekg(0, ios::beg);
    cout << "size of the file is " << inputSize << " bytes"<< endl;

    //devide input into characters using 'h' delimeter
    int count = 0;
    bool result = true;
    string charSequence = "0x";
    unsigned char characterInput = '0';
    std::vector<string> cipherChars;
    while(count < inputSize){
        characterInput = inputBuffer.get();
        charSequence += characterInput;
        if(characterInput == 'h'){
            cipherChars.push_back(charSequence);
            charSequence = "0x";
        }
        count++;
    }
    
    //decrypt one char at a time
    AutoSeededRandomPool prng;
    
    for(int i = 0; i < cipherChars.size(); i++){
        //convert cipher of a character to Integer
        Integer cipher(cipherChars[i].c_str());
        if(i == 0){
            cout << " first cipher is  " << hex << cipher << endl;
        }
        //decrypt cipher of the character
        Integer pText = privKey.CalculateInverse(prng, cipher);
        //convert decrypted Integer to a string
        string recovered;
        size_t req = pText.MinEncodedSize();
        recovered.resize(req);
        pText.Encode((byte *)recovered.data(), recovered.size());
        //write decrypted char to a file
        output << recovered;
    }
    //close file streams
    input.close();
    output.close();


}