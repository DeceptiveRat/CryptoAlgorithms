#pragma once

#include <vector>
#include <array>

std::array<uint8_t, 16> generate128BitKey();

// generateRoundKey	input: 4 32bit values
//				   output: 4 32bit values
std::array<uint32_t, 4> generateRoundKey(std::array<uint32_t, 4> W, int rcValue);

// gFunctionForRoundKey	input: 4 8bit values
//					   output: 1 32bit value
uint32_t gFunctionForRoundKey(std::array<uint8_t, 4> v, int rcValue);

// extensionFieldMultiplication input: 2 8bit values
//							   output: 1 8bit value
uint8_t extensionFieldMultiplication(uint8_t Byte1, uint8_t Byte2);

// extensionFieldAddition input: 2 8bit values
//						 output: 1 8bit value
uint8_t extensionFieldAddition(uint8_t Byte1, uint8_t Byte2);

// extensionFieldAddition4Bytes input: 2 32bit values
//							   output: 1 32bit value
uint32_t extensionFieldAddition4Bytes(uint32_t Byte1, uint32_t Byte2);

// returnBinary input: 1 8bit value
//			   output: 8 1bit values
std::array<char, 8> returnBinary(uint8_t value);

// returnBinary4Byte input: 1 32bit value
//					output: 32 1bit values
std::array<char, 32> returnBinary4Byte(uint32_t value);

// returnAsNumber input: 8 1bit values
//				 output: 1 8bit value
uint8_t returnAsNumber(char* start);

// returnAs4ByteNumber input: 32 1bit values
//					  output: 1 32bit value
uint32_t returnAs4ByteNumber(char* start);

// addKey input: 4 32bit values, 4 32bit keys
//		 output: 16 8bit values
std::array<uint8_t, 16> addKey(std::array<uint32_t, 4> C, std::array<uint32_t, 4> keys);


// =================================== Encryption functions ===================================

// PKCS7padding input: 16 1bit values
//			   output: 16 1bit values
std::array<uint8_t, 16> PKCS7padding(std::array<uint8_t, 16> text, int size);

// plainToCipher input: string of undetermined length
//				output: array vector of undetermined length
std::vector<std::array<uint8_t, 16>> plainToCipher(std::string plainText);

// ECBencrypt input: string of undetermined length
//			 output: string of undetermined length
std::string ECBencrypt(std::string plainText, std::array<uint8_t, 16> firstKey);

// substitutionBox	input: 1 8bit value
//				   output: 1 8bit value
uint8_t substitutionBox(uint8_t input);

// AESround	input: 16 8bit values, 4 32bit keys, 1 int value
//		   output: 16 8bit values
std::array<uint8_t, 16> AESround(std::array<uint8_t, 16> A, std::array<uint32_t, 4> keys, int roundNum);

// mixColumn input: 4 8bit values
//			output: 4 8bit values
std::array<uint8_t, 4> mixColumn(std::array<uint8_t, 4> A);


// =================================== Decryption functions ===================================

// ECBdecrypt input: string of undetermined length
//			 output: string of undetermined length
std::string ECBdecrypt(std::string encryptedText, std::array<uint8_t, 16> firstKey);

// AESdecryptRound input: 16 8bit values, 4 32bit keys
//				  output: 16 8bit values
std::array<uint8_t, 16> AESdecryptRound(std::array<uint8_t, 16> block, std::array<uint32_t, 4> key, int roundNum);

// invertedMixColumn input: 16 8bit values
//					output: 16 8bit values
std::array<uint8_t, 16> invertedMixColumn(std::array<uint8_t, 16> A);

// inverseSubstitutionBox input: 1 8bit value
//						 output: 1 8bit value
uint8_t inverseSubstitutionBox(uint8_t input);

// stringToVectorOfBlocks input: string of undetermined length
//						 output: array vector of undetermined length
std::vector<std::array<uint8_t, 16>> stringToVectorOfBlocks(std::string text);