#include <random>
#include <vector>
#include <cstring>
#include <cstdint>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>

#include "AES_Encryption.h"

const unsigned char sBox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

const unsigned char mixColumnMatrix[4][4] = {
    {02, 03, 01, 01},
    {01, 02, 03, 01},
    {01, 01, 02, 03},
    {03, 01, 01, 02}
};

const unsigned char inverseMixColumnsMatrix[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};

const unsigned char inverseSBox[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

const unsigned char rc[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

std::array<uint8_t, 16> generate128BitKey()
{
	std::random_device rd;
	std::mt19937_64 gen(rd());
	std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);

	uint64_t keyPart1 = dis(gen);
	uint64_t keyPart2 = dis(gen);

    std::array<uint8_t, 16> keyBytes;
    std::memcpy(keyBytes.data(), &keyPart1, sizeof(uint64_t));
    std::memcpy(keyBytes.data() + 8, &keyPart2, sizeof(uint64_t));

	return keyBytes;
}

std::array<uint32_t, 4> generateRoundKey(std::array<uint32_t, 4> W, int rcValue)
{
    std::array<uint8_t, 4> v;
    std::memcpy(v.data(), W.data() + 3, 4);

    W[0] = extensionFieldAddition4Bytes(W[0], gFunctionForRoundKey(v, rcValue));

    for (int i = 1; i < 4; i++)
    {
        W[i] = extensionFieldAddition4Bytes(W[i], W[i - 1]);
    }

    return W;
}

uint32_t gFunctionForRoundKey(std::array<uint8_t, 4> v, int rcValue)
{
    uint32_t returnValue = 0;
    std::array<uint8_t, 4> afterShift = { 0 };

    for (int i = 0; i < 4; i++)
    {
        afterShift[i] = v[(i + 1) % 4];
        afterShift[i] = substitutionBox(afterShift[i]);
    }

    afterShift[0] = extensionFieldAddition(afterShift[0], rc[rcValue]); // for the first 8 bits, XOR them with values from the round coefficients

    std::memcpy(&returnValue, afterShift.data(), 4);

    return returnValue;
}

uint8_t substitutionBox(uint8_t input)
{
	uint8_t row;
	uint8_t column;

	row = input >> 4;
	column = input & 15;

    return sBox[row][column];
}

std::array<uint8_t, 16> AESround(std::array<uint8_t, 16> A, std::array<uint32_t, 4> keys, int roundNum)
{
    for (int i = 0; i < 16; i++)
        A[i] = substitutionBox(A[i]);

    std::array<uint32_t, 4> C;
    std::array<uint8_t, 4> beforeColumnMix;
    std::array<uint8_t, 4> afterColumnMix;

    if (roundNum == 10)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                beforeColumnMix[j] = (A[(i * 4 + 5 * j) % 16]); // shift rows layer
            }

            for (int j = 0; j < 4; j++)
            {
                std::memcpy(&C[i], beforeColumnMix.data(), 4);
            }
        }

        return addKey(C, keys); // key addition layer
    }

    for (int i = 0; i < 4; i ++)
    {
        for (int j = 0; j < 4; j++)
        {
            beforeColumnMix[j] = (A[(i * 4 + 5 * j) % 16]); // shift rows layer
        }

        afterColumnMix = mixColumn(beforeColumnMix); // mix column layer

        for (int j = 0; j < 4; j++)
        {
            std::memcpy(&C[i], afterColumnMix.data(), 4);
        }
    }

    return addKey(C, keys); // key addition layer
}

uint8_t extensionFieldMultiplication(uint8_t Byte1, uint8_t Byte2)
{
    std::array<char, 8> bit1 = returnBinary(Byte1);
    std::array<char, 8> bit2 = returnBinary(Byte2);

    std::array<char, 15> multiply = { 0 };

    for (int i = 0; i < 8; i++)
    {
        if(bit1[i] == 1)
        {
            for (int j = 0; j < 8; j++)
            {
                if (bit2[j] == 1)
                    multiply[i + j]++;
            }
        }
    }

    for (int i = 0; i < 15; i++)
        multiply[i] %= 2;

    for (int i = 0; i < 7; i++)
    {
        if (multiply[i] % 2) 
        {
            multiply[i + 4]++; // A*x^4
            multiply[i + 5]++; // A*x^3
            multiply[i + 7]++; // A*x^1
            multiply[i + 8]++; // A*x^0
        }
    }

    uint8_t returnValue = 0;

    returnValue = returnAsNumber(&multiply[7]);

    return returnValue;
}

uint8_t extensionFieldAddition(uint8_t Byte1, uint8_t Byte2)
{
    std::array<char, 8> bit1 = returnBinary(Byte1);
    std::array<char, 8> bit2 = returnBinary(Byte2);

    std::array<char, 8> returnValueBits = { 0 };

    for (int i = 0; i < 8; i++)
        returnValueBits[i] = (bit1[i] + bit2[i]) % 2;

    uint8_t returnValue = returnAsNumber(&returnValueBits[0]);

    return returnValue;
}

uint32_t extensionFieldAddition4Bytes(uint32_t Byte1, uint32_t Byte2)
{
    std::array<char, 32> bit1 = returnBinary4Byte(Byte1);
    std::array<char, 32> bit2 = returnBinary4Byte(Byte2);

    std::array<char, 32> returnValueBits = { 0 };

    for (int i = 0; i < 32; i++)
        returnValueBits[i] = (bit1[i] + bit2[i]) % 2;

    uint32_t returnValue = returnAs4ByteNumber(&returnValueBits[0]);

    return returnValue;
}

std::array<uint8_t, 4> mixColumn(std::array<uint8_t, 4> A)
{
    std::array<uint8_t, 4> returnValue = { 0 };

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            returnValue[i] = extensionFieldAddition(extensionFieldMultiplication(mixColumnMatrix[i][j], A[j]), returnValue[i]);
        }
    }

    return returnValue;
}

std::array<char, 8> returnBinary(uint8_t value)
{
    std::array<char, 8> returnValue = { 0 };

    for (int i = 0; i < 8; i++)
        returnValue[i] = (value >> (7 - i)) & 1;

    return returnValue;
}

std::array<char, 32> returnBinary4Byte(uint32_t value)
{
    std::array<char, 32> returnValue = { 0 };

    for (int i = 0; i < 32; i++)
        returnValue[i] = (value >> (31 - i)) & 1;

    return returnValue;
}

uint8_t returnAsNumber(char* start)
{
    uint8_t returnValue = 0;

    for (int i = 0; i < 8; i++)
    {
        start[i] %= 2;
        returnValue |= (start[i] << (7 - i));
    }

    return returnValue;
}

uint32_t returnAs4ByteNumber(char* start)
{
    uint32_t returnValue = 0;

    for (int i = 0; i < 32; i++)
    {
        start[i] %= 2;
        returnValue |= (start[i] << (31 - i));
    }

    return returnValue;
}

std::array<uint8_t, 16> addKey(std::array<uint32_t, 4> C, std::array<uint32_t, 4> keys)
{
    std::array<uint8_t, 16> returnValue = { 0 };

    for (int i = 0; i < 4; i++)
    {
        C[i] = extensionFieldAddition4Bytes(C[i], keys[i]);
    }

    std::memcpy(returnValue.data(), C.data(), 16);

    return returnValue;
}

std::array<uint8_t, 16> PKCS7padding(std::array<uint8_t, 16> text, int size)
{
    char c = 16 - size;

    for (int i = size; i < 16; i++)
        text[i] = c;

    return text;
}

std::vector<std::array<uint8_t, 16>> plainToCipher(std::string plainText) // 1 char -> 1 Byte
{
    std::vector<std::array<uint8_t, 16>> cipherText;
    std::array<uint8_t, 16> textBlock = { 0 };

    while (plainText.size() > 15)
    {
        for (int i = 0; i < 16; i++)
        {
            textBlock[i] = plainText[i];
        }

        plainText.erase(0, 16);
        cipherText.push_back(textBlock);
    }

     std::memcpy(&textBlock, plainText.data(), plainText.size());
     textBlock = PKCS7padding(textBlock, plainText.size());
     cipherText.push_back(textBlock);

     return cipherText;
}

std::string ECBencrypt(std::string plainText, std::array<uint8_t, 16> firstKey)
{
    std::vector<std::array<uint8_t, 16>> text;
    text = plainToCipher(plainText);

    std::array<std::array<uint32_t, 4>, 11> keyArray = { 0 };

    std::memcpy(keyArray[0].data(), firstKey.data(), 16);

    for (int i = 1; i < 11; i++)
    {
        keyArray[i] = generateRoundKey(keyArray[i - 1], i - 1);
    }

     for (int blockNum = 0; blockNum < (int)text.size(); blockNum++)
    {
        for (int i = 0; i < 16; i++) // first key addition
        {
            text[blockNum][i] = extensionFieldAddition(text[blockNum][i], firstKey[i]);
        }

        for (int i = 0; i < 10; i++)
        {
            text[blockNum] = AESround(text[blockNum], keyArray[i+1], i + 1);
        }
    }

    std::stringstream encryptedString;

    for (const auto& block : text)
    {
        for (int i = 0; i < 16; i++)
            encryptedString << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(block[i]);
    }

    return encryptedString.str();
}

std::string ECBdecrypt(std::string encryptedText, std::array<uint8_t, 16> firstKey)
{
    std::vector<std::array<uint8_t, 16>> encryptedTextAsBlocks;

    encryptedTextAsBlocks = stringToVectorOfBlocks(encryptedText);

    // create a key array to get keys from
    std::array<std::array<uint32_t, 4>, 11> keyArray = { 0 };

    std::memcpy(keyArray[0].data(), firstKey.data(), 16);

    for (int i = 1; i < 11; i++)
    {
        keyArray[i] = generateRoundKey(keyArray[i - 1], i - 1);
    }

    for (int i = 0; i < (int)encryptedTextAsBlocks.size(); i++) // decrypt each block
    {
        for (int j = 0; j < 10; j++) // repeat 10 times for each block to be decrypted
        {
            encryptedTextAsBlocks[i] = AESdecryptRound(encryptedTextAsBlocks[i], keyArray[10 - j], j + 1);
        }

        for (int j = 0; j < 16; j++)
        {
            encryptedTextAsBlocks[i][j] = extensionFieldAddition(encryptedTextAsBlocks[i][j], firstKey[j]);
            if (encryptedTextAsBlocks[i][j] >= 1 && encryptedTextAsBlocks[i][j] <= 16)
            {
                if(encryptedTextAsBlocks[i][j] != 10)
                    encryptedTextAsBlocks[i][j] = 0;
            }
        }
    }

    if (encryptedTextAsBlocks[encryptedTextAsBlocks.size() - 1][0] == 0) // if the last block starts with 0 delete that block
        encryptedTextAsBlocks.pop_back();

    std::stringstream decryptedText;

    for (const auto& decrytedTextBlock : encryptedTextAsBlocks)
    {
        for (int i = 0; i < 16; i++)
        {
            decryptedText << decrytedTextBlock[i];
        }
    }
    

    return decryptedText.str();
}

std::array<uint8_t, 16> AESdecryptRound(std::array<uint8_t, 16> valueInBytes, std::array<uint32_t, 4> key, int roundNum)
{
    std::array<uint8_t, 16> keyByte = { 0 };
    std::memcpy(keyByte.data(), key.data(), 16);

    // key addition layer
    for (int i = 0; i < 16; i++)
        valueInBytes[i] = extensionFieldAddition(valueInBytes[i], keyByte[i]);

    // inverted mix column layer
    std::array<uint8_t, 16> afterMixColumn = { 0 };

    if (roundNum != 1)
    {
        afterMixColumn = invertedMixColumn(valueInBytes);
    }
    
    else
    {
        afterMixColumn = valueInBytes;
    }

    // inverted shift rows layer
    std::array<uint8_t, 16> afterShiftRows = { 0 };
    std::array<uint8_t, 16> afterShiftRowsWatch = { 0 }; 

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            afterShiftRows[4 * i + j] = afterMixColumn[(i * 4 + 16 - 3 * j) % 16]; // inverse shift rows
            afterShiftRowsWatch = afterShiftRows;
        }
    }

    // inverted byte substitution layer
    for (int i = 0; i < 16; i++)
    {
        afterShiftRows[i] = inverseSubstitutionBox(afterShiftRows[i]);
        afterShiftRowsWatch = afterShiftRows;
    }

    return afterShiftRows;
}

std::array<uint8_t, 16> invertedMixColumn(std::array<uint8_t, 16> A)
{
    std::array<uint8_t, 16> returnValue = { 0 };
    std::array<uint8_t, 16> returnValueWatch = { 0 };

    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            returnValue[i] = extensionFieldAddition(extensionFieldMultiplication(inverseMixColumnsMatrix[i % 4][j], A[(i / 4) * 4 + j]), returnValue[i]);
            returnValueWatch[i] = returnValue[i];
        }
    }

    return returnValue;
}

uint8_t inverseSubstitutionBox(uint8_t input)
{
    uint8_t row;
    uint8_t column;

    row = input >> 4;
    column = input & 15;

    return inverseSBox[row][column];
}

std::vector<std::array<uint8_t, 16>> stringToVectorOfBlocks(std::string text) 
{
    std::vector<std::array<uint8_t, 16>> returnValue;
    std::array<uint8_t, 16> textBlock = { 0 };

    if (text.size() % 32 != 0)
        throw std::runtime_error("Text size is not a multiple of 32!");

    while (text.size() > 0)
    {
        for (int i = 0; i < 16; i++)
        {
            textBlock[i] = std::stoi(text.substr(0, 2), nullptr, 16);
            text.erase(0, 2);
        }

        returnValue.push_back(textBlock);
    }

    return returnValue;
}
