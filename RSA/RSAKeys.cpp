#include "cryptopp/cryptlib.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"

#include <iostream>
#include <string>
#include <sstream>

using namespace CryptoPP;
using namespace std;

int main(int argc, char * argv[]){

    cout << "RSA Key Generation!" << endl;

    AutoSeededRandomPool prng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048);

    RSA::PrivateKey privKey(params);
    RSA::PublicKey pubKey(params);

    cout << "Modulus: " << hex << privKey.GetModulus() << endl;
    cout << "Public exponent: " << hex << privKey.GetPublicExponent() << endl;
    cout << "Private exponent: " << hex << privKey.GetPrivateExponent() << endl;

}