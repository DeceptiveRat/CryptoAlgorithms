#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace RSA 
{
	// encryption option
	//typedef uint8_t BLOCKSIZEUSED;
	//typedef uint16_t DOUBLEBLOCKSIZE;
	//constexpr short blockCount = 16;
	//constexpr short primeTestTries = 5;
	//constexpr short blockSizeInBits = 8;
	//constexpr short blockSizeInBytes = 1;
	//constexpr DOUBLEBLOCKSIZE ByteMask = UINT8_MAX;
	//constexpr BLOCKSIZEUSED blockMSB = 0x80;

	typedef uint32_t BLOCKSIZEUSED;
	typedef uint64_t DOUBLEBLOCKSIZE;
	constexpr int blockCount = 4;
	constexpr int primeTestTries = 8;
	constexpr int blockSizeInBytes = sizeof(BLOCKSIZEUSED);
	constexpr int blockSizeInBits = blockSizeInBytes*8;
	constexpr BLOCKSIZEUSED ByteMask = UINT32_MAX;
	constexpr BLOCKSIZEUSED blockMSB = 0x80000000;
	constexpr int decimalArrayBlockSize = (blockCount * 12 / 10) + 1;

	constexpr std::array<BLOCKSIZEUSED, blockCount> zeroInBlocks = { 0 };
	constexpr std::array<BLOCKSIZEUSED, blockCount*2> zeroInDoubleBlocks = { 0 };

	bool MillerRabinPrimalityTest(std::array<BLOCKSIZEUSED, blockCount> nAsArrayOfBlocks);

	void randomNum(std::array<BLOCKSIZEUSED, blockCount>* ptrToA);

	void modularExponentiation(std::array<BLOCKSIZEUSED, blockCount> base, std::array<BLOCKSIZEUSED, blockCount*2> exponent,
		std::array<BLOCKSIZEUSED, blockCount>* dst, std::array<BLOCKSIZEUSED, blockCount> modulus);

	void modularExponentiation(std::array<BLOCKSIZEUSED, blockCount*2> base, int exponent,
		std::array<BLOCKSIZEUSED, blockCount*2>* dst, std::array<BLOCKSIZEUSED, blockCount*2> modulus);

	void multiplication(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y,
		std::array<BLOCKSIZEUSED, blockCount*2>* dst);

	bool additionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount*2> X, std::array<BLOCKSIZEUSED, blockCount*2> Y,
		std::array<BLOCKSIZEUSED, blockCount*2>* dst);

	bool additionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y,
		std::array<BLOCKSIZEUSED, blockCount>* dst);

	bool isCoprime(std::array<BLOCKSIZEUSED, blockCount> a, std::array<BLOCKSIZEUSED, blockCount> b);

	void gcd(std::array<BLOCKSIZEUSED, blockCount> a, std::array<BLOCKSIZEUSED, blockCount> b,
		std::array<BLOCKSIZEUSED, blockCount>* dst);

	void modularFunctionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount*2> dividend,
		std::array<BLOCKSIZEUSED, blockCount> modulus, std::array<BLOCKSIZEUSED, blockCount>* dst,
		int lengthOfDividend, int lengthOfModulus);

	void modularFunctionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount> dividend,
		std::array<BLOCKSIZEUSED, blockCount> modulus, std::array<BLOCKSIZEUSED, blockCount>* dst,
		int lengthOfDividend, int lengthOfModulus);

	void modularFunctionForVectorOfBlocks(std::vector<BLOCKSIZEUSED> dividend, int dividendLength, std::vector<BLOCKSIZEUSED> modulus, int modulusLength, std::vector<BLOCKSIZEUSED>* dst, int dstLength);

	BLOCKSIZEUSED addition(DOUBLEBLOCKSIZE X, std::array<BLOCKSIZEUSED, blockCount * 2> Y, int indexOfBlock,
		std::array<BLOCKSIZEUSED, blockCount * 2>* dst);

	BLOCKSIZEUSED addition(DOUBLEBLOCKSIZE X, std::array<BLOCKSIZEUSED, blockCount> Y, int indexOfBlock, std::array<BLOCKSIZEUSED, blockCount>* dst);

	bool XBiggerThanYWhenMatched(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y, int length, std::array<BLOCKSIZEUSED, blockCount>* dst, int* leftShiftLeft, BLOCKSIZEUSED* discardedValue);

	/*
		Align X and Y and compare them. True is returned if X is bigger or they are the equal. False is returned if Y is bigger.
	*/
	bool bitAlignedCompare(std::vector<BLOCKSIZEUSED> X, int XelementCount, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount, int* leftShiftLeft, BLOCKSIZEUSED* discardedValue);

	void modularSubtraction(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y,
		std::array<BLOCKSIZEUSED, blockCount>* dst, int length);

	int lengthOfArrayOfBlock(std::array<BLOCKSIZEUSED, blockCount> a);

	int lengthOfArrayOfBlock(std::array<BLOCKSIZEUSED, blockCount * 2> a);

	int lengthOfVectorOfBlock(std::vector<BLOCKSIZEUSED> vec, int vecLength);

	BLOCKSIZEUSED shiftArray(std::array<BLOCKSIZEUSED, blockCount> arrayToShift, const int shiftBy, const bool shiftLeft,
		std::array<BLOCKSIZEUSED, blockCount>* dst, const int arrayStartIndex);

	BLOCKSIZEUSED shiftArray(std::array<BLOCKSIZEUSED, blockCount*2> arrayToShift, const int shiftBy, const bool shiftLeft,
		std::array<BLOCKSIZEUSED, blockCount*2>* dst, const int arrayStartIndex);

	BLOCKSIZEUSED shiftVector(std::vector<BLOCKSIZEUSED> vectorToShift, const int vectorElementCount, std::vector<BLOCKSIZEUSED>* dst, const int dstElementCount, const int vectorStartIndex, const int shiftBy, const bool shiftLeft);

	void randomNumSmallerThan(std::array<BLOCKSIZEUSED, blockCount>* ptrToA, const std::array<BLOCKSIZEUSED, blockCount> X,
		const int xLength);

	std::string arrayToDecimal(std::array<BLOCKSIZEUSED, blockCount * 2> arrayToConvert);

	bool equals(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y);

	void stringToArray(std::string convertString, std::array<BLOCKSIZEUSED, blockCount*2>* dst);
	
	std::string encryptString(std::string plainText, std::array<BLOCKSIZEUSED, blockCount*2> n, int e);

	std::vector<std::array<BLOCKSIZEUSED, blockCount*2>> stringToVectorOfArrays(std::string const plainText);

	bool additionForVectorOfBlocks(std::vector<BLOCKSIZEUSED> X, int XelementCount, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount);

	void modularSubtraction(std::vector<BLOCKSIZEUSED> X, int XelementCount, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount);

	bool MillerRabinPrimalityTest(std::vector<BLOCKSIZEUSED> nAsArrayOfBlocks, int nElementCount);

	void randomNumSmallerThan(std::vector<BLOCKSIZEUSED>* ptrToA, const int AelementCount, const std::vector<BLOCKSIZEUSED> X, const int XelementCount, const int xLength);

	int compareVec(std::vector<BLOCKSIZEUSED> X, const int XelementCount, std::vector<BLOCKSIZEUSED> Y, const int YelementCount);

	void gcd(std::vector<BLOCKSIZEUSED> X, const int XelementCount, std::vector<BLOCKSIZEUSED> Y, const int YelementCount, std::vector<BLOCKSIZEUSED>* dst, const int dstElementCount);

	void modularExponentiation(std::vector<BLOCKSIZEUSED> base, int baseElementCount, std::vector<BLOCKSIZEUSED> modulus, int modulusElementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount, int exponent);

	void modularExponentiation(std::vector<BLOCKSIZEUSED> base, int baseElementCount, std::vector<BLOCKSIZEUSED> exponent, int exponentElementCount, std::vector<BLOCKSIZEUSED> modulus, int modulusElementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount);

	void randomNum(std::vector<BLOCKSIZEUSED>* X, const int XelementCount);

	void multiplication(std::vector<BLOCKSIZEUSED> X, int Xlength, std::vector<BLOCKSIZEUSED> Y, int Ylength, std::vector<BLOCKSIZEUSED>* dst, int dstLength);

	BLOCKSIZEUSED addition(DOUBLEBLOCKSIZE X, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount, int indexOfBlock);

	int getStartIndex(std::vector<BLOCKSIZEUSED> X, int XelementCount);
} 
