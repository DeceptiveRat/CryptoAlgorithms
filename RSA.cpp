#include <array>
#include <cstdint>
#include <random>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <sstream>

#include "RSA.h"

using namespace RSA;

bool RSA::MillerRabinPrimalityTest(std::array<BLOCKSIZEUSED, blockCount> nAsArrayOfBlocks)
{
	int k = primeTestTries; // k in Miller-Rabin primality test. Number of times to try.

	std::array<BLOCKSIZEUSED, blockCount*2> d = { 0 };

	if ((nAsArrayOfBlocks[blockCount - 1] & 1) == 0) // nAsArrayOfBlocks was even, so not prime
		return false;
	else
		nAsArrayOfBlocks[blockCount - 1] -= 1; // nAsArrayOfBlocks was odd so make it even

	int r = 0; // the r in: n - 1 = d * (2^r)

	while (1) // find the first occurance of 1 going left from the least significant bit
	{
		if ((nAsArrayOfBlocks[blockCount - 1 - (r / blockSizeInBits)] >> r & 1) == 1)
		{
			break;
		}
		 
		else
		{
			r++;
		}
	}

	const short bitShiftRight = (r % blockSizeInBits);
	const short dLengthInBlocks = blockCount - (r / blockSizeInBits);
	const BLOCKSIZEUSED rLSBmask = ByteMask >> (blockSizeInBits - bitShiftRight); // least significant r bits are 1
	BLOCKSIZEUSED rLSBs = 0;
	BLOCKSIZEUSED prevBlockrLSBs = 0;

	for (int i = 0; i < dLengthInBlocks; i++) // no need to shift some of the least signifcant blocks
	{	// shift the individual elements in the array and save to d
		prevBlockrLSBs = rLSBs << (blockSizeInBits - bitShiftRight);
		rLSBs = nAsArrayOfBlocks[i] & rLSBmask;
		d[blockCount * 2 - dLengthInBlocks + i] = nAsArrayOfBlocks[i] >> bitShiftRight;
		d[blockCount * 2 - dLengthInBlocks + i] |= prevBlockrLSBs;
	}

	nAsArrayOfBlocks[blockCount - 1] += 1; // 1 was subtracted for d now add 1 again because n has to be used as the modulus

	// it would be great if I can figure out how to make these arrays dLengthInBlocks long.
	std::array<BLOCKSIZEUSED, blockCount> a = { 0 };
	std::array<BLOCKSIZEUSED, blockCount> aToThePowerOfd = { 0 };
	std::array<BLOCKSIZEUSED, blockCount> greatestCommonDivisor = { 0 };
	std::array<BLOCKSIZEUSED, blockCount> aToThePowerOfdIncremented = { 0 };

	for (int j = 0; j < k; j++)
	{

		std::memcpy(aToThePowerOfd.data(), zeroInBlocks.data(), blockSizeInBytes * blockCount);

		randomNumSmallerThan(&a, nAsArrayOfBlocks, lengthOfArrayOfBlock(nAsArrayOfBlocks));

		gcd(a, nAsArrayOfBlocks, &greatestCommonDivisor);
		while (greatestCommonDivisor[blockCount -1] != 1 || lengthOfArrayOfBlock(greatestCommonDivisor) != 1)
		{
			std::memcpy(aToThePowerOfd.data(), zeroInBlocks.data(), blockSizeInBytes * blockCount);
			randomNumSmallerThan(&a, nAsArrayOfBlocks, lengthOfArrayOfBlock(nAsArrayOfBlocks));
			gcd(a, nAsArrayOfBlocks, &greatestCommonDivisor);
		}

		modularExponentiation(a, d, &aToThePowerOfd, nAsArrayOfBlocks);

		addition(1, aToThePowerOfd, blockCount - 1, &aToThePowerOfdIncremented);

		if (aToThePowerOfd[dLengthInBlocks - 1] == 1 && lengthOfArrayOfBlock(aToThePowerOfd) == 1)  // passes for this witness
		{
			continue;
		}

		else
		{
			for (int i = 0; i < r; i++)
			{
				if (equals(nAsArrayOfBlocks, aToThePowerOfdIncremented)) // passes for this witness
				{
					break;
				}

				else
				{
					shiftArray(d, 1, true, &d, lengthOfArrayOfBlock(d)); // probably will start with the 0th block anyway no need to add the overhead of calculating where to start for each block
					modularExponentiation(a, d, &aToThePowerOfd, nAsArrayOfBlocks);
					addition(1, aToThePowerOfd, blockCount - 1, &aToThePowerOfdIncremented);
				}
			}

			if (equals(nAsArrayOfBlocks, aToThePowerOfdIncremented)) // passes for this witness
			{
				continue;
			}

			else
			{
				return false;
			}
		}
	}

	return true;
}

void RSA::randomNum(std::array<BLOCKSIZEUSED, blockCount>* ptrToA)
{
	std::random_device rd;
	std::mt19937 gen(rd());

	std::uniform_int_distribution<uint64_t> dist(2, ByteMask);

	std::array<BLOCKSIZEUSED, blockCount> arrayOfA = { 0 };

	for (int i = 0; i < blockCount; i++)
	{
		arrayOfA[i] = dist(gen);
	}

	std::memcpy(ptrToA->data(), arrayOfA.data(), blockSizeInBytes * blockCount);
}

void RSA::modularExponentiation(std::array<BLOCKSIZEUSED, blockCount> base, std::array<BLOCKSIZEUSED, blockCount*2> exponent,
	std::array<BLOCKSIZEUSED, blockCount>* dst, std::array<BLOCKSIZEUSED, blockCount> modulus)
{
	std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };
	std::array<BLOCKSIZEUSED, blockCount*2> multipliedValue = { 0 };
	returnValue[blockCount - 1] = 1;

	bool currentValueOfBit;
	int i = 0;
	int j = 0;

	for (i = 0; i < blockCount*2; i++) // get the first instance of 1 from the left. This is where to begin.
	{
		if (exponent[i] == 0)
		{
			continue;
		}

		for (j = 0; j < blockSizeInBits; j++)
		{
			currentValueOfBit = exponent[i] & (1 << (blockSizeInBits - 1 - j));
			if (currentValueOfBit == 1)
			{
				break;
			}
		}

		if (currentValueOfBit == 1)
		{
			break;
		}
	}

	for (; i < blockCount*2; i++)
	{
		for (; j < blockSizeInBits; j++)
		{
			currentValueOfBit = exponent[i] & (1 << (blockSizeInBits - 1 - j));

			std::memcpy(multipliedValue.data(), zeroInBlocks.data(), blockSizeInBytes * blockCount);
			std::memcpy(multipliedValue.data() + blockCount, zeroInBlocks.data(), blockSizeInBytes * blockCount);

			multiplication(returnValue, returnValue, &multipliedValue); // square 
			modularFunctionForArrayOfBlocks(multipliedValue, modulus, &returnValue, lengthOfArrayOfBlock(multipliedValue), lengthOfArrayOfBlock(modulus));

			if (currentValueOfBit == 1)
			{
				multiplication(returnValue, base, &multipliedValue); // multiply
				modularFunctionForArrayOfBlocks(multipliedValue, modulus, &returnValue, lengthOfArrayOfBlock(multipliedValue), lengthOfArrayOfBlock(modulus));
			}
		}

		j = 0;
	}

	std::memcpy(dst->data(), returnValue.data(), blockSizeInBytes * blockCount);
}

void RSA::multiplication(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y, std::array<BLOCKSIZEUSED, blockCount*2>* dst)
{
	std::array<BLOCKSIZEUSED, blockCount*2> returnValue = { 0 };

	int XStartIndex = blockCount - lengthOfArrayOfBlock(X);
	int YStartIndex = blockCount - lengthOfArrayOfBlock(Y);

	for (int i = XStartIndex; i < blockCount; i++)
	{
		for (int j = YStartIndex; j < blockCount; j++)
		{
			if (X[i] == 0 || Y[j] == 0) // test with benchmark later
			{
				continue;
			}

			addition(static_cast<DOUBLEBLOCKSIZE>(X[i]) * Y[j], returnValue, i + j + 1, &returnValue);
		}
	}

	std::memcpy(dst->data(), returnValue.data(), blockCount * 2 * blockSizeInBytes);
}

void RSA::gcd(std::array<BLOCKSIZEUSED, blockCount> a, std::array<BLOCKSIZEUSED, blockCount> b,
	std::array<BLOCKSIZEUSED, blockCount>* dst)
{
	std::array<BLOCKSIZEUSED, blockCount> moddedResult = { 0 };

 	modularFunctionForArrayOfBlocks(a, b, &moddedResult, lengthOfArrayOfBlock(a), lengthOfArrayOfBlock(b));
	
	if (lengthOfArrayOfBlock(moddedResult) != 0)
	{
		gcd(b, moddedResult, dst);
	}

	else
	{
		int startIndex = blockCount - lengthOfArrayOfBlock(b);
		std::memcpy(dst->data() + startIndex, b.data() + startIndex, lengthOfArrayOfBlock(b) * blockSizeInBytes);
	}
}

bool RSA::additionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount * 2> X, std::array<BLOCKSIZEUSED, blockCount * 2> Y,
	std::array<BLOCKSIZEUSED, blockCount * 2>* dst)
{
	std::array<BLOCKSIZEUSED, blockCount * 2> returnValue = { 0 };
	bool carryValue = 0;
	DOUBLEBLOCKSIZE addedValue = 0;

	for (int i = (blockCount * 2) - 1; i > -1; i--)
	{
		if (X[i] == 0)
		{
			if (Y[i] == 0)
			{
				continue;
			}
			else
			{
				addedValue = static_cast<DOUBLEBLOCKSIZE>(Y[i]) + carryValue;
				returnValue[i] = addedValue & ByteMask;
				carryValue = addedValue >> blockSizeInBits;
			}
		}

		else if (Y[i] == 0)
		{
			addedValue = static_cast<DOUBLEBLOCKSIZE>(X[i]) + carryValue;
			returnValue[i] = addedValue & ByteMask;
			carryValue = addedValue >> blockSizeInBits;
		}

		else
		{
			addedValue = static_cast<DOUBLEBLOCKSIZE>(X[i]) + Y[i] + carryValue;
			returnValue[i] = addedValue & ByteMask; 
			carryValue = addedValue >> blockSizeInBits;
		}
	}

	std::memcpy(dst->data(), returnValue.data(), blockCount * 2 * blockSizeInBytes);

	return carryValue;
}

BLOCKSIZEUSED RSA::addition(DOUBLEBLOCKSIZE X, std::array<BLOCKSIZEUSED, blockCount * 2> Y, int indexOfBlock,
	std::array<BLOCKSIZEUSED, blockCount * 2>* dst)
{
	std::array<BLOCKSIZEUSED, blockCount * 2> returnValue = { 0 };
	BLOCKSIZEUSED carryValue = 0;
	DOUBLEBLOCKSIZE addedValue = 0;

	addedValue = X + Y[indexOfBlock] + carryValue;
	returnValue[indexOfBlock] = addedValue & ByteMask;
	carryValue = addedValue >> blockSizeInBits;

	for (int i = indexOfBlock - 1; i > -1; i--)
	{
		addedValue = static_cast<DOUBLEBLOCKSIZE>(Y[i]) + carryValue;
		returnValue[i] = addedValue & ByteMask; 
		carryValue = addedValue >> blockSizeInBits;
	}

	std::memcpy(dst->data(), returnValue.data(), (indexOfBlock + 1) * blockSizeInBytes);

	return carryValue;
}

bool RSA::XBiggerThanYWhenMatched(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y,
	int length, std::array<BLOCKSIZEUSED, blockCount>* dst, int* leftShiftLeft, BLOCKSIZEUSED* discardedValue)
{
	short firstOneX = -1;
	short firstOneY = -1;
	BLOCKSIZEUSED isBitOne = blockMSB;
	int firstBlockIndex = blockCount - length;
	int lengthX = lengthOfArrayOfBlock(X);
	int firstBlockIndexX = blockCount - lengthX;

	for (int j = firstBlockIndexX; j < blockCount; j++)
	{
		for (int i = 0; i < blockSizeInBits; i++)
		{
			if (X[j] & isBitOne)
			{
				firstOneX = i + (blockSizeInBits * (j - firstBlockIndex));
				break;
			}

			isBitOne = isBitOne >> 1;
		}

		if (firstOneX != -1)
		{
			break;
		}

		isBitOne = blockMSB;
	}

	isBitOne = blockMSB;

	for (int i = 0; i < blockSizeInBits; i++)
	{
		if (Y[firstBlockIndex] & isBitOne)
		{
			firstOneY = i;
			break;
		}
	
		isBitOne = isBitOne >> 1;
	}

	int shiftRightBy = firstOneY - firstOneX;

	*leftShiftLeft += shiftRightBy;

	if (*leftShiftLeft < 0)
	{
		shiftRightBy -= *leftShiftLeft;
	}

	if (shiftRightBy < 0) // X has to be shifted left
	{
		int shiftByteLeft = 0;
		int shiftBitLeft = 0;

		shiftByteLeft = -shiftRightBy / blockSizeInBits;
		shiftBitLeft = -shiftRightBy % blockSizeInBits;

		if (shiftByteLeft != 0)
		{
			std::memcpy(X.data() + firstBlockIndexX - shiftByteLeft, X.data() + firstBlockIndexX, lengthX * blockSizeInBytes); //shift blocks

			firstBlockIndexX -= shiftByteLeft;

			for (int i = firstBlockIndexX + lengthX + 1; i < blockCount; i++) // ERROR HERE
			{
				X[i] = 0;
			}
		}

		if (firstBlockIndexX - 1 >= 0)
			X[firstBlockIndexX - 1] |= ((X[firstBlockIndexX]) >> (blockSizeInBits - shiftBitLeft));

		for (int i = firstBlockIndexX; i < firstBlockIndexX + lengthX - 1; i++)
		{
			X[i] = X[i] << shiftBitLeft;
			X[i] |= ((X[i + 1]) >> (blockSizeInBits - shiftBitLeft));
		}

		X[firstBlockIndexX + lengthX - 1] = X[firstBlockIndexX + lengthX - 1] << shiftBitLeft;
		
		if (firstBlockIndexX - 1 >= 0)
			std::memcpy(dst->data() + firstBlockIndexX - 1, X.data() + firstBlockIndexX - 1, (lengthX + 1) * blockSizeInBytes);
		else
			std::memcpy(dst->data() + firstBlockIndexX, X.data() + firstBlockIndexX, lengthX * blockSizeInBytes);

		for (int i = firstBlockIndex; i < firstBlockIndex + length - shiftByteLeft; i++)
		{
			if (X[i] > Y[i])
			{
				return true;
			}

			else if (X[i] < Y[i])
			{
				return false;
			}
		}

		for (int i = firstBlockIndex + length - shiftByteLeft + 1; i < blockCount; i++)
		{
			if (Y[i] != 0)
				return false;
		}

		return true; // since we are finding the first instance where X either bigger or the same
	}

	else if (shiftRightBy > 0) // X has to be shifted right
	{
		*discardedValue += shiftArray(X, shiftRightBy, false, &X, firstBlockIndex);

		std::memcpy(dst->data() + firstBlockIndex, X.data() + firstBlockIndex, length * blockSizeInBytes);

		for (int i = firstBlockIndex; i < blockCount; i++)
		{
			if (X[i] > Y[i])
			{
				return true;
			}

			else if (X[i] < Y[i])
			{
				return false;
			}
		}

		return true;
	}

	else // doesn't have to be shifted
	{
		std::memcpy(dst->data() + firstBlockIndex, X.data() + firstBlockIndex, length* blockSizeInBytes);

		for (int i = firstBlockIndex; i < blockCount; i++)
		{
			if (X[i] > Y[i])
			{
				return true;
			}

			else if (X[i] < Y[i])
			{
				return false;
			}
		}

		return true;
	}
}

void RSA::modularSubtraction(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y,
	std::array<BLOCKSIZEUSED, blockCount>* dst, int length)
{
	std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };

	BLOCKSIZEUSED carryValue = 0;

	int firstValueIndex = blockCount - length;
	for (int i = blockCount - 1; i >= firstValueIndex ; i--)
	{
		returnValue[i] = X[i] - Y[i] - carryValue;
		if (Y[i] + carryValue > X[i])
		{
			carryValue = 1;
		}

		else
		{
			carryValue = 0;
		}
	}

	std::memcpy(dst->data() + (firstValueIndex), returnValue.data() + (firstValueIndex), length * blockSizeInBytes);
}

int RSA::lengthOfArrayOfBlock(std::array<BLOCKSIZEUSED, blockCount> a)
{
	for (int i = 0; i < blockCount; i++)
	{
		if (a[i] != 0)
			return blockCount - i;
	}

	return 0;
}

int RSA::lengthOfArrayOfBlock(std::array<BLOCKSIZEUSED, blockCount*2> a)
{
	for (int i = 0; i < blockCount*2; i++)
	{
		if (a[i] != 0)
			return blockCount*2 - i;
	}

	return 0;
}

void RSA::modularFunctionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount*2> dividend,
	std::array<BLOCKSIZEUSED, blockCount> modulus, std::array<BLOCKSIZEUSED, blockCount>* dst,
	int lengthOfDividend, int lengthOfModulus)
{
	if (lengthOfDividend < lengthOfModulus)
	{
		std::memcpy(dst->data() + blockCount - lengthOfDividend, dividend.data() + blockCount*2 - lengthOfDividend, lengthOfDividend * blockSizeInBytes);
		return;
	}

	else if (lengthOfDividend == lengthOfModulus)
	{
		for (int i = blockCount - lengthOfModulus; i < blockCount; i++)
		{
			if (dividend[i + blockCount] > modulus[i])
			{
				break;
			}

			else if (dividend[i + blockCount] < modulus[i])
			{
				std::memcpy(dst->data() + blockCount - lengthOfDividend, dividend.data() + blockCount*2 - lengthOfDividend, lengthOfDividend * blockSizeInBytes);
				return;
			}

			else
			{
				if (i == blockCount - 1)
				{
					std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };
					std::memcpy(dst->data() + blockCount - lengthOfModulus, returnValue.data() + blockCount - lengthOfModulus, lengthOfModulus * blockSizeInBytes);
					return;
				}
			}
		}
	}

	std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };
	std::array<BLOCKSIZEUSED, blockCount> valueToSubtract = { 0 };
	int leftShiftLeft = 0;
	int modulusStartIndex = blockCount - lengthOfModulus;
	int startOfDividendIndex = 0;
	bool isXbigger = false;
	BLOCKSIZEUSED discardedValue = 0;
	bool returnValueOverflow = 0;

	if (lengthOfModulus == 1)
	{
		DOUBLEBLOCKSIZE moddedValue = 0;

		for (int i = blockCount * 2 - lengthOfDividend; i < blockCount * 2; i++)
		{
			leftShiftLeft = (blockCount * 2 - i - 1) * blockSizeInBits;
			moddedValue = dividend[i];

			while (leftShiftLeft != 0)
			{
				moddedValue = moddedValue << (blockSizeInBits / 8);
				moddedValue %= modulus[blockCount - 1];
				leftShiftLeft -= (blockSizeInBits / 8);
			}

			moddedValue %= modulus[blockCount - 1];

			addition(moddedValue, returnValue, blockCount - 1, &returnValue);
		}

		modularFunctionForArrayOfBlocks(returnValue, modulus, &returnValue, lengthOfArrayOfBlock(returnValue), 1);

		std::memcpy(dst->data() + modulusStartIndex, returnValue.data() + modulusStartIndex, lengthOfModulus * blockSizeInBytes);
	}

	else
	{
		for (int i = 0; i < ((lengthOfDividend - 1) / lengthOfModulus) + 1; i++)
		{
			discardedValue = 0;

			leftShiftLeft = i * blockSizeInBits * lengthOfModulus;
			startOfDividendIndex = blockCount*2 - lengthOfModulus * (i + 1);

			if (startOfDividendIndex > -1)
			{
				std::memcpy(valueToSubtract.data() + modulusStartIndex, dividend.data() + startOfDividendIndex, lengthOfModulus * blockSizeInBytes);
			}

			else
			{
				for (int j = modulusStartIndex; j <= -startOfDividendIndex; j++)
				{
					valueToSubtract[j] = 0;
				}

				std::memcpy(valueToSubtract.data() + modulusStartIndex - startOfDividendIndex, dividend.data(), (lengthOfModulus + startOfDividendIndex) * blockSizeInBytes);
			}

			if (leftShiftLeft == 0) // it's okay to right shift when the values that get "discarded" remain the same size
			{
				isXbigger = XBiggerThanYWhenMatched(valueToSubtract, modulus, lengthOfModulus, &valueToSubtract, &leftShiftLeft, &discardedValue);

				if (!isXbigger)
				{
					if (leftShiftLeft <= 0) // X is smaller than Y even after the full shift
					{
						returnValueOverflow = additionForArrayOfBlocks(valueToSubtract, returnValue, &returnValue);
						if (returnValueOverflow == 1 || modulus[modulusStartIndex] < returnValue[modulusStartIndex])
						{
							modularSubtraction(returnValue, modulus, &returnValue, lengthOfModulus);
							returnValueOverflow = 0;
						}

						addition(discardedValue, returnValue, blockCount - 1, &returnValue);
						continue;
					}

					else
					{
						shiftArray(valueToSubtract, 1, true, &valueToSubtract, modulusStartIndex);
						leftShiftLeft--;

						modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
					}
				}

				else
				{
					modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
				}
			}

			else // value that is discarded when right shifted are those values * 2^n so in this case it's better to get the modded value some other way
			{
				modularFunctionForArrayOfBlocks(valueToSubtract, modulus, &valueToSubtract, lengthOfArrayOfBlock(valueToSubtract), lengthOfModulus); // there might be a better way than this function call
			}

			while (1)
			{
				if (lengthOfArrayOfBlock(valueToSubtract) == 0)
					return;

				isXbigger = XBiggerThanYWhenMatched(valueToSubtract, modulus, lengthOfModulus, &valueToSubtract, &leftShiftLeft, &discardedValue);

				if (!isXbigger)
				{
					if (leftShiftLeft <= 0) // X is smaller than Y even after the full shift
					{
						returnValueOverflow = additionForArrayOfBlocks(valueToSubtract, returnValue, &returnValue);
						if (returnValueOverflow == 1 || modulus[modulusStartIndex] < returnValue[modulusStartIndex])
						{
							modularSubtraction(returnValue, modulus, &returnValue, lengthOfModulus);
							returnValueOverflow = 0;
						}

						addition(discardedValue, returnValue, blockCount - 1, &returnValue);
						break;
					}

					else
					{
						shiftArray(valueToSubtract, 1, true, &valueToSubtract, modulusStartIndex);
						leftShiftLeft--;

						modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
					}
				}

				else
				{
					modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
				}
			}
		}

		for (int i = modulusStartIndex; i < blockCount; i++)
		{
			if (returnValue[i] > modulus[i])
			{
				modularFunctionForArrayOfBlocks(returnValue, modulus, &returnValue, lengthOfModulus, lengthOfModulus);
				break;
			}

			else if (returnValue[i] < modulus[i])
			{
				break;
			}

			else
			{
				if (i == blockCount - 1)
				{
					for (int j = modulusStartIndex; j < blockCount; j++)
					{
						returnValue[j] = 0;
					}
				}
			}
		}

		std::memcpy(dst->data() + modulusStartIndex, returnValue.data() + modulusStartIndex, lengthOfModulus * blockSizeInBytes);
	}
}

bool RSA::isCoprime(std::array<BLOCKSIZEUSED, blockCount> a, std::array<BLOCKSIZEUSED, blockCount> b)
{
	std::array<BLOCKSIZEUSED, blockCount> greatestCommonDivisor = { 0 };

	gcd(a, b, &greatestCommonDivisor);
	if (lengthOfArrayOfBlock(greatestCommonDivisor) == 1 && greatestCommonDivisor[blockCount - 1] == 1)
	{
		return true;
	}

	else
	{
		return false;
	}
}

BLOCKSIZEUSED RSA::shiftArray(std::array<BLOCKSIZEUSED, blockCount> arrayToShift, const int shiftBy,
	const bool shiftLeft, std::array<BLOCKSIZEUSED, blockCount>* dst, const int arrayStartIndex)
{
	if (shiftBy >= blockSizeInBits || shiftBy < 1)
	{
		std::cout << "WRONG SHIFT VALUE!";
		throw std::runtime_error("WRONG VALUE IS SHIFTED");
		return false;
	}

	BLOCKSIZEUSED returnValue = 0;

	if (shiftLeft)
	{
		returnValue = arrayToShift[arrayStartIndex] >> (blockSizeInBits - shiftBy);

		for (int j = arrayStartIndex; j < blockCount - 1; j++)
		{
			arrayToShift[j] = arrayToShift[j] << shiftBy;
			arrayToShift[j] |= arrayToShift[j + 1] >> (blockSizeInBits - shiftBy);
		}

		arrayToShift[blockCount - 1] = arrayToShift[blockCount - 1] << shiftBy;
	}
	
	else
	{
		returnValue = arrayToShift[blockCount - 1] & (ByteMask >> (blockSizeInBits - shiftBy));

		for (int j = blockCount - 1; j >  arrayStartIndex ; j--)
		{
			arrayToShift[j] = arrayToShift[j] >> shiftBy;
			arrayToShift[j] |= arrayToShift[j - 1] << (blockSizeInBits - shiftBy);
		}

		arrayToShift[arrayStartIndex] = arrayToShift[arrayStartIndex] >> shiftBy;
	}

	std::memcpy(dst->data() + arrayStartIndex, arrayToShift.data() + arrayStartIndex, (blockCount - arrayStartIndex) * blockSizeInBytes);

	return returnValue;
}

BLOCKSIZEUSED RSA::shiftArray(std::array<BLOCKSIZEUSED, blockCount * 2> arrayToShift, const int shiftBy,
	const bool shiftLeft, std::array<BLOCKSIZEUSED, blockCount * 2>* dst, const int arrayStartIndex)
{
	if (shiftBy >= blockSizeInBits || shiftBy < 1)
	{
		std::cout << "WRONG SHIFT VALUE!";
		throw std::runtime_error("WRONG VALUE IS SHIFTED");
		return false;
	}

	BLOCKSIZEUSED returnValue = 0;

	if (shiftLeft)
	{
		returnValue = arrayToShift[arrayStartIndex] >> (blockSizeInBits - shiftBy);

		for (int j = arrayStartIndex; j < blockCount*2 - 1; j++)
		{
			arrayToShift[j] = arrayToShift[j] << shiftBy;
			arrayToShift[j] |= arrayToShift[j + 1] >> (blockSizeInBits - shiftBy);
		}

		arrayToShift[blockCount*2 - 1] = arrayToShift[blockCount * 2 - 1] << shiftBy;
	}

	else
	{
		returnValue = arrayToShift[blockCount * 2 - 1] & (ByteMask >> (blockSizeInBits - shiftBy));

		for (int j = blockCount * 2 - 1; j > arrayStartIndex; j--)
		{
			arrayToShift[j] = arrayToShift[j] >> shiftBy;
			arrayToShift[j] |= arrayToShift[j - 1] << (blockSizeInBits - shiftBy);
		}

		arrayToShift[arrayStartIndex] = arrayToShift[arrayStartIndex] >> shiftBy;
	}

	std::memcpy(dst->data() + arrayStartIndex, arrayToShift.data() + arrayStartIndex, (blockCount*2 - arrayStartIndex) * blockSizeInBytes);

	return returnValue;
}

void RSA::randomNumSmallerThan(std::array<BLOCKSIZEUSED, blockCount>* ptrToA, const std::array<BLOCKSIZEUSED, blockCount> X,
	const int xLength)
{
	std::random_device rd;
	std::mt19937 gen(rd());

	int xStartIndex = blockCount - xLength;
	std::uniform_int_distribution<uint64_t> dist(2, ByteMask);
	std::uniform_int_distribution<uint64_t> smallerThanX0(1, X[xStartIndex]);

	std::array<BLOCKSIZEUSED, blockCount> arrayOfA = { 0 };

	arrayOfA[xStartIndex] = smallerThanX0(gen);

	if (arrayOfA[xStartIndex] == X[xStartIndex])
	{
		std::memcpy(ptrToA->data() + xStartIndex, arrayOfA.data() + xStartIndex, blockSizeInBytes);
		randomNumSmallerThan(ptrToA, X, xLength - 1);
	}

	else
	{
		for (int i = xStartIndex + 1; i < blockCount; i++)
		{
			arrayOfA[i] = dist(gen);
		}

		std::memcpy(ptrToA->data() + xStartIndex, arrayOfA.data() + xStartIndex, xLength * blockSizeInBytes);
	}
}

BLOCKSIZEUSED RSA::addition(DOUBLEBLOCKSIZE X, std::array<BLOCKSIZEUSED, blockCount> Y,
	int indexOfBlock, std::array<BLOCKSIZEUSED, blockCount>* dst)
{
	std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };
	BLOCKSIZEUSED carryValue = 0;
	DOUBLEBLOCKSIZE addedValue = 0;

	addedValue = static_cast<DOUBLEBLOCKSIZE>(X) + Y[indexOfBlock] + carryValue;
	returnValue[indexOfBlock] = addedValue & ByteMask;
	carryValue = addedValue >> blockSizeInBits;

	for (int i = indexOfBlock - 1; i > -1; i--)
	{
		addedValue = static_cast<DOUBLEBLOCKSIZE>(Y[i]) + carryValue;
		returnValue[i] = addedValue & ByteMask;
		carryValue = addedValue >> blockSizeInBits;
	}

	std::memcpy(dst->data(), returnValue.data(), (indexOfBlock + 1) * blockSizeInBytes);

	return carryValue;
}

void RSA::modularFunctionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount> dividend,
	std::array<BLOCKSIZEUSED, blockCount> modulus, std::array<BLOCKSIZEUSED, blockCount>* dst,
	int lengthOfDividend, int lengthOfModulus)
{
	if (lengthOfDividend < lengthOfModulus)
	{
		std::memcpy(dst->data() + blockCount - lengthOfDividend, dividend.data() + blockCount - lengthOfDividend, lengthOfDividend * blockSizeInBytes);
		return;
	}

	else if (lengthOfDividend == lengthOfModulus)
	{
		for (int i = blockCount - lengthOfModulus; i < blockCount; i++)
		{
			if (dividend[i] > modulus[i])
			{
				break;
			}

			else if (dividend[i] < modulus[i])
			{
				std::memcpy(dst->data() + blockCount - lengthOfDividend, dividend.data() + blockCount - lengthOfDividend, lengthOfDividend * blockSizeInBytes);
				return;
			}

			else
			{
				if (i == blockCount - 1)
				{
					std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };
					std::memcpy(dst->data() + blockCount - lengthOfModulus, returnValue.data() + blockCount - lengthOfModulus, lengthOfModulus * blockSizeInBytes);
					return;
				}
			}
		}
	}

	std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };
	std::array<BLOCKSIZEUSED, blockCount> valueToSubtract = { 0 };
	int leftShiftLeft = 0;
	int modulusStartIndex = blockCount - lengthOfModulus;
	int startOfDividendIndex = 0;
	bool isXbigger = false;
	BLOCKSIZEUSED discardedValue = 0;
	bool returnValueOverflow = 0;

	if (lengthOfModulus == 1)
	{
		DOUBLEBLOCKSIZE moddedValue = 0;

		for (int i = blockCount - lengthOfDividend; i < blockCount; i++)
		{
			leftShiftLeft = (blockCount - i - 1) * blockSizeInBits;
			moddedValue = dividend[i];

			while (leftShiftLeft != 0)
			{
				moddedValue = moddedValue << (blockSizeInBits / 8);
				moddedValue %= modulus[blockCount - 1];
				leftShiftLeft -= (blockSizeInBits / 8);
			}

			moddedValue %= modulus[blockCount - 1];

			addition(moddedValue, returnValue, blockCount - 1, &returnValue);
		}

		modularFunctionForArrayOfBlocks(returnValue, modulus, &returnValue, lengthOfArrayOfBlock(returnValue), 1);

		std::memcpy(dst->data() + modulusStartIndex, returnValue.data() + modulusStartIndex, lengthOfModulus * blockSizeInBytes);
	}

	else
	{
		for (int i = 0; i < ((lengthOfDividend - 1) / lengthOfModulus) + 1; i++)
		{
			discardedValue = 0;

			leftShiftLeft = i * blockSizeInBits * lengthOfModulus;
			startOfDividendIndex = blockCount - lengthOfModulus * (i + 1);

			if (startOfDividendIndex > -1)
			{
				std::memcpy(valueToSubtract.data() + modulusStartIndex, dividend.data() + startOfDividendIndex, lengthOfModulus * blockSizeInBytes);
			}

			else
			{
				for (int j = modulusStartIndex; j <= -startOfDividendIndex; j++)
				{
					valueToSubtract[j] = 0;
				}

				std::memcpy(valueToSubtract.data() + modulusStartIndex - startOfDividendIndex, dividend.data(), (lengthOfModulus + startOfDividendIndex) * blockSizeInBytes);
			}

			if (leftShiftLeft == 0) // it's okay to right shift when the values that get "discarded" remain the same size
			{
				isXbigger = XBiggerThanYWhenMatched(valueToSubtract, modulus, lengthOfModulus, &valueToSubtract, &leftShiftLeft, &discardedValue);

				if (!isXbigger)
				{
					if (leftShiftLeft <= 0) // X is smaller than Y even after the full shift
					{
						returnValueOverflow = additionForArrayOfBlocks(valueToSubtract, returnValue, &returnValue);
						if (returnValueOverflow == 1 || modulus[modulusStartIndex] < returnValue[modulusStartIndex])
						{
							modularSubtraction(returnValue, modulus, &returnValue, lengthOfModulus);
							returnValueOverflow = 0;
						}

						addition(discardedValue, returnValue, blockCount - 1, &returnValue);
						continue;
					}

					else
					{
						shiftArray(valueToSubtract, 1, true, &valueToSubtract, modulusStartIndex);
						leftShiftLeft--;

						modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
					}
				}

				else
				{
					modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
				}
			}

			else // value that is discarded when right shifted are those values * 2^n so in this case it's better to get the modded value some other way
			{
				modularFunctionForArrayOfBlocks(valueToSubtract, modulus, &valueToSubtract, lengthOfArrayOfBlock(valueToSubtract), lengthOfModulus); // there might be a better way than this function call
			}

			while (1)
			{
				if (lengthOfArrayOfBlock(valueToSubtract) == 0)
					return;

				isXbigger = XBiggerThanYWhenMatched(valueToSubtract, modulus, lengthOfModulus, &valueToSubtract, &leftShiftLeft, &discardedValue);

				if (!isXbigger)
				{
					if (leftShiftLeft <= 0) // X is smaller than Y even after the full shift
					{
						returnValueOverflow = additionForArrayOfBlocks(valueToSubtract, returnValue, &returnValue);
						if (returnValueOverflow == 1 || modulus[modulusStartIndex] < returnValue[modulusStartIndex])
						{
							modularSubtraction(returnValue, modulus, &returnValue, lengthOfModulus);
							returnValueOverflow = 0;
						}

						addition(discardedValue, returnValue, blockCount - 1, &returnValue);
						break;
					}

					else
					{
						shiftArray(valueToSubtract, 1, true, &valueToSubtract, modulusStartIndex);
						leftShiftLeft--;

						modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
					}
				}

				else
				{
					modularSubtraction(valueToSubtract, modulus, &valueToSubtract, lengthOfModulus);
				}
			}
		}

		for (int i = modulusStartIndex; i < blockCount; i++)
		{
			if (returnValue[i] > modulus[i])
			{
				modularFunctionForArrayOfBlocks(returnValue, modulus, &returnValue, lengthOfModulus, lengthOfModulus);
				break;
			}

			else if (returnValue[i] < modulus[i])
			{
				break;
			}

			else
			{
				if (i == blockCount - 1)
				{
					for (int j = modulusStartIndex; j < blockCount; j++)
					{
						returnValue[j] = 0;
					}
				}
			}
		}

		std::memcpy(dst->data() + modulusStartIndex, returnValue.data() + modulusStartIndex, lengthOfModulus * blockSizeInBytes);
	}
}

bool RSA::additionForArrayOfBlocks(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y,
	std::array<BLOCKSIZEUSED, blockCount>* dst)
{
	std::array<BLOCKSIZEUSED, blockCount> returnValue = { 0 };
	bool carryValue = 0;
	DOUBLEBLOCKSIZE addedValue = 0;

	for (int i = blockCount - 1; i > -1; i--)
	{
		if (X[i] == 0)
		{
			if (Y[i] == 0)
			{
				continue;
			}
			else
			{
				addedValue = static_cast<DOUBLEBLOCKSIZE>(Y[i]) + carryValue;
				returnValue[i] = addedValue & ByteMask;
				carryValue = addedValue >> blockSizeInBits;
			}
		}

		else if (Y[i] == 0)
		{
			addedValue = static_cast<DOUBLEBLOCKSIZE>(X[i]) + carryValue;
			returnValue[i] = addedValue & ByteMask;
			carryValue = addedValue >> blockSizeInBits;
		}

		else
		{
			addedValue = static_cast<DOUBLEBLOCKSIZE>(X[i]) + Y[i] + carryValue;
			returnValue[i] = addedValue & ByteMask;
			carryValue = addedValue >> blockSizeInBits;
		}
	}

	std::memcpy(dst->data(), returnValue.data(), blockCount * blockSizeInBytes);

	return carryValue;
}

bool RSA::equals(std::array<BLOCKSIZEUSED, blockCount> X, std::array<BLOCKSIZEUSED, blockCount> Y)
{
	if (lengthOfArrayOfBlock(X) != lengthOfArrayOfBlock(Y))
		return false;

	for (int i = 0; i < blockCount - 1; i++)
	{
		if (X[i] != Y[i])
			return false;
	}

	return true;
}

void RSA::stringToArray(std::string convertString, std::array<BLOCKSIZEUSED, blockCount*2>* dst)
{
	std::array<BLOCKSIZEUSED, blockCount*2 - 1> returnValue = {0};
	int charInBlock = blockSizeInBytes/sizeof(char);
	while((int)convertString.size()%charInBlock != 0)
	{
		convertString = '\0' + convertString;
	}
	int convertStringBlockLength = ((int)convertString.size()/charInBlock);
	const unsigned char* stringPtr = reinterpret_cast<const unsigned char*>(convertString.data());

	if(convertStringBlockLength > blockCount*2 - 1)
	{
		throw std::runtime_error("Tried to convert a string that is too big!");
	}

	for (int i = convertStringBlockLength -1; i >= 0; --i)
	{
		for(int j =0;j<charInBlock;j++)
		{
			returnValue[i] += static_cast<BLOCKSIZEUSED>(stringPtr[charInBlock*i + j])<<(8*(charInBlock - 1-j));
		}
	}

	std::memcpy(dst->data() + blockCount*2 - convertStringBlockLength, returnValue.data(), blockSizeInBytes * convertStringBlockLength);
}

std::string RSA::encryptString(std::string plainText, std::array<BLOCKSIZEUSED, blockCount*2> n, int e)
{
	std::vector<std::array<BLOCKSIZEUSED, blockCount*2>> plainTextVector;
	plainTextVector = stringToVectorOfArrays(plainText);
	
	return "";
}

std::vector<std::array<BLOCKSIZEUSED, blockCount*2>> RSA::stringToVectorOfArrays(std::string plainText)
{
	std::vector<std::array<BLOCKSIZEUSED, blockCount*2>> returnValue;
	std::array<BLOCKSIZEUSED, blockCount*2> arrayOfBlocks;
	int charInArray = sizeof(BLOCKSIZEUSED)/sizeof(char) * ((blockCount*2)-1);
	while((int)plainText.length() > 0)
	{
		std::memcpy(arrayOfBlocks.data(), zeroInDoubleBlocks.data(), blockSizeInBytes * blockCount*2);
		stringToArray(plainText.substr(0, charInArray), &arrayOfBlocks);
		returnValue.push_back(arrayOfBlocks);
		plainText.erase(0, charInArray);
	}

	return returnValue;
}
/*
void RSA::modularExponentiation(std::array<BLOCKSIZEUSED, blockCount*2> base, int exponent, std::array<BLOCKSIZEUSED, blockCount*2>* dst, std::array<BLOCKSIZEUSED, blockCount*2> modulus)
{
	std::array<BLOCKSIZEUSED, blockCount*2> returnValue = { 0 };
	std::array<BLOCKSIZEUSED, blockCount*4> multipliedValue = { 0 };
	returnValue[blockCount*2 - 1] = 1;

	bool currentValueOfBit;
	int j = 0;

	for (j = 0; j < sizeof(int)*8; j++)
	{
		currentValueOfBit = exponent & (1 << (sizeof(int)*8 - 1 - j));
		if (currentValueOfBit == 1)
		{
			break;
		}
	}

	for (; j < blockSizeInBits; j++)
	{
		currentValueOfBit = exponent & (1 << (sizeof(int)*8 - 1 - j));

		std::memcpy(multipliedValue.data(), zeroInDoubleBlocks.data(), blockSizeInBytes * blockCount*2);
		std::memcpy(multipliedValue.data() + blockCount*2, zeroInDoubleBlocks.data(), blockSizeInBytes * blockCount*2);

		multiplication(returnValue, returnValue, &multipliedValue); // square 
		modularFunctionForArrayOfBlocks(multipliedValue, modulus, &returnValue, lengthOfArrayOfBlock(multipliedValue), lengthOfArrayOfBlock(modulus));

		if (currentValueOfBit == 1)
		{
			multiplication(returnValue, base, &multipliedValue); // multiply
			modularFunctionForArrayOfBlocks(multipliedValue, modulus, &returnValue, lengthOfArrayOfBlock(multipliedValue), lengthOfArrayOfBlock(modulus));
		}
	}

	j = 0;

	std::memcpy(dst->data(), returnValue.data(), blockSizeInBytes * blockCount);
}
*/
void RSA::modularExponentiation(std::vector<BLOCKSIZEUSED> base, int baseElementCount, std::vector<BLOCKSIZEUSED> modulus, int modulusElementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount, int exponent)
{
	if(modulusElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the modulus. From modExpo function");
	else if(baseElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the base. From modExpo function");
	else if(dstElementCount != baseElementCount + modulusElementCount)
		throw std::runtime_error("Wrong element count for the dst. From modExpo function");

	int baseLength = lengthOfVectorOfBlock(base, baseElementCount);
	int baseStartIndex = baseElementCount - baseLength;
	int modulusLength = lengthOfVectorOfBlock(modulus, modulusElementCount);
	int modulusStartIndex = modulusElementCount - modulusLength;

	std::vector<BLOCKSIZEUSED> returnValue(dstElementCount);
	int multValueElementCount = dstElementCount*2;
	std::vector<BLOCKSIZEUSED> multipliedValue(multValueElementCount);
	returnValue[dstElementCount- 1] = 1;

	int zeroCopyCount = multValueElementCount/blockCount;

	bool currentValueOfBit;
	int j = 0;

	for (j = 0; j < (int)sizeof(BLOCKSIZEUSED)*8; ++j)
	{
		currentValueOfBit = exponent & (1 << (sizeof(BLOCKSIZEUSED)*8 - 1 - j));
		if (currentValueOfBit == 1)
		{
			break;
		}
	}

	for (; j < blockSizeInBits; ++j)
	{
		currentValueOfBit = exponent & (1 << (sizeof(BLOCKSIZEUSED)*8 - 1 - j));

		// multipliedValue is reset to 0
		for(int k = 0;k<zeroCopyCount;++k)
			std::memcpy(multipliedValue.data() + blockCount*k, zeroInBlocks.data(), blockCount*blockSizeInBytes);

		multiplication(returnValue, dstElementCount, returnValue, dstElementCount, &multipliedValue, multValueElementCount); // square 
		modularFunctionForVectorOfBlocks(multipliedValue, multValueElementCount, modulus, modulusElementCount, &returnValue, modulusElementCount);

		if(currentValueOfBit)
		{
			multiplication(returnValue, dstElementCount, base, baseElementCount, &multipliedValue, multValueElementCount); // multiply
			modularFunctionForVectorOfBlocks(multipliedValue, multValueElementCount, modulus, modulusElementCount, &returnValue, modulusElementCount);
		}
	}

	std::memcpy(dst->data(), returnValue.data(), blockSizeInBytes * dstElementCount);
}

void RSA::modularExponentiation(std::vector<BLOCKSIZEUSED> base, int baseElementCount, std::vector<BLOCKSIZEUSED> exponent, int exponentElementCount, std::vector<BLOCKSIZEUSED> modulus, int modulusElementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount)
{
	if(modulusElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the modulus. From modExpo function");
	else if(baseElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the base. From modExpo function");
	else if(dstElementCount != modulusElementCount)
		throw std::runtime_error("Wrong element count for the dst. From modExpo function");
	else if(exponentElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the exponent. From modExpo function");

	int baseLength = lengthOfVectorOfBlock(base, baseElementCount);
	int baseStartIndex = baseElementCount - baseLength;
	int modulusLength = lengthOfVectorOfBlock(modulus, modulusElementCount);
	int modulusStartIndex = modulusElementCount - modulusLength;
	int exponentLength = lengthOfVectorOfBlock(exponent, exponentElementCount);
	int exponentStartIndex = exponentElementCount - exponentLength;

	std::vector<BLOCKSIZEUSED> returnValue(dstElementCount);
	int multValueElementCount = dstElementCount*2;
	std::vector<BLOCKSIZEUSED> multipliedValue(multValueElementCount);
	returnValue[dstElementCount- 1] = 1;

	bool currentValueOfBit;
	int i = 0;
	int j = 0;

	int zeroCopyCount = multValueElementCount/blockCount;

	for (i = 0; i < exponentElementCount; ++i) // get the first instance of 1 from the left. This is where to begin.
	{
		if (exponent[i] == 0)
		{
			continue;
		}

		for (j = 0; j < blockSizeInBits; ++j)
		{
			currentValueOfBit = exponent[i] & (1 << (blockSizeInBits - 1 - j));
			if (currentValueOfBit == 1)
			{
				break;
			}
		}

		if (currentValueOfBit == 1)
		{
			break;
		}
	}

	for (; i < exponentElementCount; ++i)
	{
		for (; j < blockSizeInBits; ++j)
		{
			currentValueOfBit = exponent[i] & (1 << (blockSizeInBits - 1 - j));

			// multipliedValue is reset to 0
			for(int k = 0;k<zeroCopyCount;++k)
				std::memcpy(multipliedValue.data() + blockCount*k, zeroInBlocks.data(), blockCount*blockSizeInBytes);
		
			multiplication(returnValue, dstElementCount, returnValue, dstElementCount, &multipliedValue, multValueElementCount); // square 
			modularFunctionForVectorOfBlocks(multipliedValue, multValueElementCount, modulus, modulusElementCount, &returnValue, modulusElementCount);

			if(currentValueOfBit)
			{
				multiplication(returnValue, dstElementCount, base, baseElementCount, &multipliedValue, multValueElementCount); // multiply
				modularFunctionForVectorOfBlocks(multipliedValue, multValueElementCount, modulus, modulusElementCount, &returnValue, modulusElementCount);
			}
		}

		j = 0;
	}

	std::memcpy(dst->data(), returnValue.data(), blockSizeInBytes * dstElementCount);
}

void RSA::multiplication(std::vector<BLOCKSIZEUSED> X, int XelementCount, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount)
{
	if(XelementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for X. From mult function");
	else if(YelementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for Y. From mult function");
	else if(dstElementCount < XelementCount+YelementCount)
		throw std::runtime_error("Dst should be the size of X and Y combined. From mult function");

	int Xlength = lengthOfVectorOfBlock(X, XelementCount);
	int XstartIndex = XelementCount - Xlength;
	int Ylength = lengthOfVectorOfBlock(Y, YelementCount);
	int YstartIndex = YelementCount - Ylength;

	std::vector<BLOCKSIZEUSED> returnValue(dstElementCount);
	int dstStartIndex = XstartIndex + YstartIndex;
	
	for (int i = XstartIndex; i < XelementCount; ++i)
	{
		for (int j = YstartIndex; j < YelementCount; ++j)
		{
			if (X[i] == 0 || Y[j] == 0) // test with benchmark later
			{
				continue;
			}

			addition(static_cast<DOUBLEBLOCKSIZE>(X[i]) * Y[j], returnValue, dstElementCount, &returnValue, dstElementCount, i + j + 1);
		}
	}

	std::memcpy(dst->data() + dstStartIndex, returnValue.data() + dstStartIndex, (Xlength + Ylength) * blockSizeInBytes);
}

int RSA::lengthOfVectorOfBlock(std::vector<BLOCKSIZEUSED> vec, int vecElementCount)
{
	if(vecElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the vector. From vector length function");
	
	for (int i = 0; i < vecElementCount; i++)
	{
		if (vec[i] != 0)
			return vecElementCount - i;
	}

	return 0;
}

BLOCKSIZEUSED RSA::addition(DOUBLEBLOCKSIZE X, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount, int indexOfBlock)
{
	if(YelementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for Y. From add function");
	else if(YelementCount != dstElementCount)
		throw std::runtime_error("Dst element count doesn't equal Y size. From add function");

	std::vector<BLOCKSIZEUSED> returnValue(dstElementCount);
	BLOCKSIZEUSED carryValue = 0;
	DOUBLEBLOCKSIZE addedValue = 0;

	std::memcpy(returnValue.data(), Y.data(), dstElementCount*blockSizeInBytes);

	addedValue = X + Y[indexOfBlock] + carryValue;
	returnValue[indexOfBlock] = addedValue & ByteMask;
	carryValue = addedValue >> blockSizeInBits;

	int i = 0;

	for (i = indexOfBlock - 1; i > -1; i--)
	{
		addedValue = static_cast<DOUBLEBLOCKSIZE>(Y[i]) + carryValue;
		returnValue[i] = addedValue & ByteMask; 
		carryValue = addedValue >> blockSizeInBits;

		if(carryValue == 0)
			break;
	}

	std::memcpy(dst->data(), returnValue.data(), dstElementCount * blockSizeInBytes);

	return carryValue;
}

void RSA::modularFunctionForVectorOfBlocks(std::vector<BLOCKSIZEUSED> dividend, int dividendElementCount, std::vector<BLOCKSIZEUSED> modulus, int modulusElementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount)
{
	if(modulusElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the modulus. From mod function");
	else if(dividendElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the dividend. From mod function");
	else if(dstElementCount != modulusElementCount)
		throw std::runtime_error("Dst size doesn't match modulus size. From mod function");

	int dividendLength = lengthOfVectorOfBlock(dividend, dividendElementCount);
	int dividendStartIndex = dividendElementCount - dividendLength;
	int modulusLength = lengthOfVectorOfBlock(modulus, modulusElementCount);
	int modulusStartIndex = modulusElementCount - modulusLength;

	if (dividendLength < modulusLength)
	{
		std::memcpy(dst->data() + dstElementCount- dividendLength, dividend.data() + dividendElementCount - dividendLength, dividendLength * blockSizeInBytes);
		return;
	}

	else if (dividendLength == modulusLength) // I think I can use compareVec here right
	{
		for (int i = modulusStartIndex; i < modulusElementCount; ++i)
		{
			if (dividend[i + dividendElementCount - modulusElementCount] > modulus[i])
			{
				break;
			}

			else if (dividend[i + dividendElementCount - modulusElementCount] < modulus[i])
			{
				std::memcpy(dst->data() + dstElementCount- dividendLength, dividend.data() + dividendElementCount - dividendLength, dividendLength * blockSizeInBytes);
				return;
			}

			else
			{
				if (i == modulusElementCount - 1)
				{
					for(int k = 0;k<dstElementCount/blockCount;++k)
						std::memcpy(dst->data() + blockCount*k, zeroInBlocks.data(), blockCount*blockSizeInBytes);

					return;
				}
			}
		}
	}

	std::vector<BLOCKSIZEUSED> returnValue(modulusElementCount);
	std::vector<BLOCKSIZEUSED> valueToSubtract(modulusElementCount);
	int leftShiftLeft = 0;

	if (modulusLength == 1)
	{
		DOUBLEBLOCKSIZE moddedValue = 0;

		for (int i = dividendElementCount - dividendLength; i < dividendElementCount; ++i)
		{
			leftShiftLeft = (dividendElementCount - i - 1) * blockSizeInBits;
			moddedValue = dividend[i];

			while (leftShiftLeft != 0)
			{
				moddedValue = moddedValue << (blockSizeInBits / 8);
				moddedValue %= modulus[modulusElementCount - 1];
				leftShiftLeft -= (blockSizeInBits / 8);
			}

			moddedValue %= modulus[modulusElementCount - 1];

			addition(moddedValue, returnValue, dstElementCount, &returnValue, dstElementCount, modulusElementCount - 1);
		}

		modularFunctionForVectorOfBlocks(returnValue, dstElementCount, modulus, modulusElementCount, &returnValue, dstElementCount);

		std::memcpy(dst->data() + modulusStartIndex, returnValue.data() + modulusStartIndex, modulusLength * blockSizeInBytes);
	}

	else
	{
		int copyDividendFromIndex = 0;
		bool isDividendBigger = false;
		BLOCKSIZEUSED discardedValue = 0;
		bool returnValueOverflow = 0;

		for (int i = 0; i < ((dividendLength - 1) / modulusLength) + 1; ++i)
		{
			discardedValue = 0;

			leftShiftLeft = i * blockSizeInBits * modulusLength;
			copyDividendFromIndex = dividendElementCount- (modulusLength * (i + 1));

			if (copyDividendFromIndex > -1)
			{
				std::memcpy(valueToSubtract.data() + modulusStartIndex, dividend.data() + copyDividendFromIndex, modulusLength * blockSizeInBytes);
			}

			else
			{
				for (int j = modulusStartIndex; j < modulusStartIndex - copyDividendFromIndex; ++j)
				{
					valueToSubtract[j] = 0;
				}

				std::memcpy(valueToSubtract.data() + modulusStartIndex - copyDividendFromIndex, dividend.data(), (modulusLength + copyDividendFromIndex) * blockSizeInBytes);
			}

			if (leftShiftLeft == 0) // it's okay to right shift when the values that get "discarded" remain the same size
			{
				isDividendBigger = bitAlignedCompare(valueToSubtract, modulusElementCount, modulus, modulusElementCount, &valueToSubtract, modulusElementCount, &leftShiftLeft, &discardedValue);

				if (!isDividendBigger)
				{
					if (leftShiftLeft <= 0) // X is smaller than Y even after the full shift
					{
						returnValueOverflow = additionForVectorOfBlocks(valueToSubtract, modulusElementCount, returnValue, modulusElementCount,  &returnValue, modulusElementCount);

						if (returnValueOverflow == 1 || modulus[modulusStartIndex] < returnValue[modulusStartIndex])
						{
							modularSubtraction(returnValue, modulusElementCount, modulus, modulusElementCount, &returnValue, modulusElementCount);
							returnValueOverflow = 0;
						}

						addition(discardedValue, returnValue, modulusElementCount, &returnValue, modulusElementCount, modulusElementCount - 1);
						continue;
					}

					else
					{
						shiftVector(valueToSubtract, modulusElementCount, &valueToSubtract, modulusElementCount, modulusStartIndex, 1, true);
						leftShiftLeft--;

						modularSubtraction(valueToSubtract, modulusElementCount, modulus, modulusElementCount, &valueToSubtract, modulusElementCount);
					}
				}

				else
				{
					modularSubtraction(valueToSubtract, modulusElementCount, modulus, modulusElementCount, &valueToSubtract, modulusElementCount);
				}
			}

			else // value that is discarded when right shifted are those values * 2^n so in this case it's better to get the modded value some other way
			{
				modularFunctionForVectorOfBlocks(valueToSubtract, modulusElementCount, modulus, modulusElementCount, &valueToSubtract, modulusElementCount); // there might be a better way than this function call
			}

			while (1)
			{
				if (lengthOfVectorOfBlock(valueToSubtract, modulusElementCount) == 0)
					return;

				isDividendBigger = bitAlignedCompare(valueToSubtract, modulusElementCount, modulus, modulusElementCount, &valueToSubtract, modulusElementCount, &leftShiftLeft, &discardedValue);

				if (!isDividendBigger)
				{
					if (leftShiftLeft <= 0) // X is smaller than Y even after the full shift
					{
						returnValueOverflow = additionForVectorOfBlocks(valueToSubtract, modulusElementCount, returnValue, modulusElementCount,  &returnValue, modulusElementCount);

						if (returnValueOverflow == 1 || modulus[modulusStartIndex] < returnValue[modulusStartIndex])
						{
							modularSubtraction(returnValue, modulusElementCount, modulus, modulusElementCount, &returnValue, modulusElementCount);
							returnValueOverflow = 0;
						}

						addition(discardedValue, returnValue, modulusElementCount, &returnValue, modulusElementCount, modulusElementCount - 1);
						break;
					}

					else
					{
						shiftVector(valueToSubtract, modulusElementCount, &valueToSubtract, modulusElementCount, modulusStartIndex, 1, true);
						leftShiftLeft--;

						modularSubtraction(valueToSubtract, modulusElementCount, modulus, modulusElementCount, &valueToSubtract, modulusElementCount);
					}
				}

				else
				{
					modularSubtraction(valueToSubtract, modulusElementCount, modulus, modulusElementCount, &valueToSubtract, modulusElementCount);
				}
			}
		}

		for (int i = modulusStartIndex; i < modulusElementCount; i++)
		{
			if (returnValue[i] > modulus[i]) // if the returnValue is bigger than the modulus we have to mod it again. But maybe there is a more efficient way to do this comparing the two values whenever a value is added to returnValue. But I would need to test to see which is actually quicker. Since comparison between vectors is used often maybe I should create a function for it?
			{
				modularFunctionForVectorOfBlocks(returnValue, modulusElementCount, modulus, modulusElementCount, &returnValue, modulusElementCount);
				break;
			}

			else if (returnValue[i] < modulus[i])
			{
				break;
			}

			else
			{
				if (i == modulusElementCount - 1)
				{
					for (int j = modulusStartIndex; j < modulusElementCount; j++)
					{
						returnValue[j] = 0;
					}
				}
			}
		}

		std::memcpy(dst->data() + modulusStartIndex, returnValue.data() + modulusStartIndex, modulusLength * blockSizeInBytes);
	}
}

bool RSA::bitAlignedCompare(std::vector<BLOCKSIZEUSED> X, int XelementCount, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount, int* leftShiftLeft, BLOCKSIZEUSED* discardedValue)
{
	if(XelementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for X. From bitAlignCompare function");
	else if(YelementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for Y. From bitAlignCompare function");
	else if(dstElementCount%blockCount != 0)
		throw std::runtime_error("Wrong element count for the dst. From bitAlignCompare function");

	short firstOneX = -1;
	short firstOneY = -1;
	BLOCKSIZEUSED isBitOne = blockMSB;
	int Xlength = lengthOfVectorOfBlock(X, XelementCount);
	int XstartIndex = XelementCount - Xlength;
	int Ylength = lengthOfVectorOfBlock(Y, YelementCount);
	int YstartIndex = YelementCount - Ylength;

	for (int j = XstartIndex; j < XelementCount; j++)
	{
		for (int i = 0; i < blockSizeInBits; i++)
		{
			if (X[j] & isBitOne)
			{
				firstOneX = i + (blockSizeInBits * j);
				break;
			}

			else
				isBitOne = isBitOne >> 1;
		}

		if (firstOneX != -1)
		{
			break;
		}

		isBitOne = blockMSB;
	}

	isBitOne = blockMSB;

	for (int j = YstartIndex; j < YelementCount; j++)
	{
		for (int i = 0; i < blockSizeInBits; i++)
		{
			if (Y[j] & isBitOne)
			{
				firstOneY = i + (blockSizeInBits * j);
				break;
			}

			else
				isBitOne = isBitOne >> 1;
		}

		if (firstOneY != -1)
		{
			break;
		}

		isBitOne = blockMSB;
	}

	int shiftRightBy = firstOneY - firstOneX;

	if(*leftShiftLeft < -shiftRightBy)
	{
		shiftRightBy = -*leftShiftLeft;
		*leftShiftLeft = 0;
	}
	else
	{
		*leftShiftLeft += shiftRightBy;
	}

	if (shiftRightBy < 0) // X has to be shifted left, this happens much more often so do not change the order
	{
		int shiftBlockLeft = 0;
		int shiftBitLeft = 0;

		shiftBlockLeft = -shiftRightBy / blockSizeInBits;
		shiftBitLeft = -shiftRightBy % blockSizeInBits;

		if (shiftBlockLeft != 0)
		{
			std::memcpy(X.data() + XstartIndex - shiftBlockLeft, X.data() + XstartIndex, Xlength * blockSizeInBytes); //shift block

			XstartIndex -= shiftBlockLeft;
		}

		if (XstartIndex >= 1)
		{
			XstartIndex -= 1;
			++Xlength;
		}

		if(shiftBitLeft != 0)
		{
			for (int i = XstartIndex; i < XstartIndex + Xlength - 1; i++)
			{
				X[i] = X[i] << shiftBitLeft;
				X[i] |= ((X[i + 1]) >> (blockSizeInBits - shiftBitLeft));
			}

			X[XstartIndex + Xlength - 1] = X[XstartIndex + Xlength - 1] << shiftBitLeft;
		}
		
		// copy the data that has been shifted
		std::memcpy(dst->data() + XstartIndex, X.data() + XstartIndex, Xlength * blockSizeInBytes);
		// copy 0 to the LSblocks that should have been "moved"
		std::memcpy(dst->data() + XstartIndex + Xlength, zeroInBlocks.data(), (XelementCount - (XstartIndex + Xlength))*blockSizeInBytes);

		for (int i = XstartIndex; i < XstartIndex + Xlength; i++)
		{
			if (X[i] > Y[i])
			{
				return true;
			}

			else if (X[i] < Y[i])
			{
				return false;
			}
		}

		for (int i = XstartIndex + Xlength; i < YelementCount; i++)
		{
			// since X[i] == 0, if Y[i] != 0, Y is bigger than X when aligned
			if (Y[i] != 0)
				return false;
		}

		return true; 
	}

	else if (shiftRightBy > 0) // X has to be shifted right
	{
		*discardedValue += shiftVector(X, XelementCount, &X, XelementCount, XstartIndex, shiftRightBy, false);

		std::memcpy(dst->data() + XstartIndex, X.data() + XstartIndex, Xlength * blockSizeInBytes);

		for (int i = XstartIndex; i < XelementCount; i++)
		{
			if (X[i] > Y[i])
			{
				return true;
			}

			else if (X[i] < Y[i])
			{
				return false;
			}
		}

		return true;
	}

	else // doesn't have to be shifted
	{
		for (int i = XstartIndex; i < XelementCount; i++)
		{
			if (X[i] > Y[i])
			{
				return true;
			}

			else if (X[i] < Y[i])
			{
				return false;
			}
		}

		return true;
	}
}

BLOCKSIZEUSED RSA::shiftVector(std::vector<BLOCKSIZEUSED> vectorToShift, const int vectorElementCount, std::vector<BLOCKSIZEUSED>* dst, const int dstElementCount, const int vectorStartIndex, const int shiftBy, const bool shiftLeft)
{
	if (shiftBy >= blockSizeInBits || shiftBy < 1)
	{
		std::cout << "WRONG SHIFT VALUE!";
		throw std::runtime_error("WRONG VALUE IS SHIFTED");
		return false;
	}

	if(vectorElementCount % blockCount != 0)
		throw std::runtime_error("Wrong vector length");
	else if(dstElementCount != vectorElementCount)
		throw std::runtime_error("Wrong vector length");

	BLOCKSIZEUSED returnValue = 0;

	if (shiftLeft)
	{
		returnValue = vectorToShift[vectorStartIndex] >> (blockSizeInBits - shiftBy);

		for (int j = vectorStartIndex; j < vectorElementCount - 1; j++)
		{
			vectorToShift[j] = vectorToShift[j] << shiftBy;
			vectorToShift[j] |= vectorToShift[j + 1] >> (blockSizeInBits - shiftBy);
		}

		vectorToShift[vectorElementCount - 1] = vectorToShift[vectorElementCount - 1] << shiftBy;
	}

	else
	{
		returnValue = vectorToShift[vectorElementCount - 1] & (ByteMask >> (blockSizeInBits - shiftBy));

		for (int j = vectorElementCount - 1; j > vectorStartIndex; j--)
		{
			vectorToShift[j] = vectorToShift[j] >> shiftBy;
			vectorToShift[j] |= vectorToShift[j - 1] << (blockSizeInBits - shiftBy);
		}

		vectorToShift[vectorStartIndex] = vectorToShift[vectorStartIndex] >> shiftBy;
	}

	std::memcpy(dst->data() + vectorStartIndex, vectorToShift.data() + vectorStartIndex, (vectorElementCount- vectorStartIndex) * blockSizeInBytes);

	return returnValue;
}

bool RSA::additionForVectorOfBlocks(std::vector<BLOCKSIZEUSED> X, int XelementCount, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount)
{
	if(XelementCount % blockCount != 0)
		throw std::runtime_error("Wrong vector length");
	else if(YelementCount != XelementCount)
		throw std::runtime_error("Wrong vector length");
	else if(dstElementCount != XelementCount)
		throw std::runtime_error("Wrong vector length");

	std::vector<BLOCKSIZEUSED> returnValue(dstElementCount, 0);
	bool carryValue = 0;
	DOUBLEBLOCKSIZE addedValue = 0;

	for (int i = XelementCount - 1; i > -1; i--)
	{
		if (X[i] == 0)
		{
			if (Y[i] == 0)
			{
				continue;
			}
			else
			{
				addedValue = static_cast<DOUBLEBLOCKSIZE>(Y[i]) + carryValue;
				returnValue[i] = addedValue & ByteMask;
				carryValue = addedValue >> blockSizeInBits;
			}
		}

		else if (Y[i] == 0)
		{
			addedValue = static_cast<DOUBLEBLOCKSIZE>(X[i]) + carryValue;
			returnValue[i] = addedValue & ByteMask;
			carryValue = addedValue >> blockSizeInBits;
		}

		else
		{
			addedValue = static_cast<DOUBLEBLOCKSIZE>(X[i]) + Y[i] + carryValue;
			returnValue[i] = addedValue & ByteMask; 
			carryValue = addedValue >> blockSizeInBits;
		}
	}

	std::memcpy(dst->data(), returnValue.data(), dstElementCount * blockSizeInBytes);

	return carryValue;
}

void RSA::modularSubtraction(std::vector<BLOCKSIZEUSED> X, int XelementCount, std::vector<BLOCKSIZEUSED> Y, int YelementCount, std::vector<BLOCKSIZEUSED>* dst, int dstElementCount)
{
	if(XelementCount % blockCount != 0)
		throw std::runtime_error("Wrong vector length");
	else if(XelementCount != YelementCount)
		throw std::runtime_error("Wrong vector length");
	else if(XelementCount != dstElementCount)
		throw std::runtime_error("Wrong vector length");

	std::vector<BLOCKSIZEUSED> returnValue(dstElementCount, 0);

	bool carryValue = 0;
	int firstValueIndex = 0;

	if(lengthOfVectorOfBlock(X, XelementCount) == 0)
		firstValueIndex = dstElementCount - lengthOfVectorOfBlock(Y, YelementCount);	

	else
		firstValueIndex = dstElementCount - lengthOfVectorOfBlock(X, XelementCount);

	for (int i = XelementCount - 1; i >= firstValueIndex ; --i)
	{
		returnValue[i] = X[i] - Y[i] - carryValue;
		if (Y[i] + carryValue > X[i])
		{
			carryValue = 1;
		}

		else
		{
			carryValue = 0;
		}
	}

	if(lengthOfVectorOfBlock(X, XelementCount) == 0)
		std::memcpy(dst->data() + firstValueIndex, returnValue.data() + firstValueIndex, lengthOfVectorOfBlock(Y, YelementCount) * blockSizeInBytes);
	else
		std::memcpy(dst->data() + firstValueIndex, returnValue.data() + firstValueIndex, lengthOfVectorOfBlock(X, XelementCount) * blockSizeInBytes);
}

// probably won't need this but I need to test if all the functions work properly anyway and this is the perfect way to try
bool RSA::MillerRabinPrimalityTest(std::vector<BLOCKSIZEUSED> n, int nElementCount)
{
	int k = primeTestTries; // k in Miller-Rabin primality test. Number of times to try.

	// d is 2 times the size of n because it has to be modularly exponentiated later
	int dElementCount = nElementCount*2;
	std::vector<BLOCKSIZEUSED> d(dElementCount);

	if ((n[nElementCount - 1] & 1) == 0) // nAsArrayOfBlocks was even, so not prime
		return false;
	else
		n[nElementCount - 1] -= 1; // nAsArrayOfBlocks was odd so make it even

	int r = 0; // the r in: n - 1 = d * (2^r)

	while (1) // find the first occurance of 1 going left from the least significant bit. Pretty sure there is a more elegant way to do this but it is so unlikely the LSblock is going to be 0 so I'll leave it as it is for now.
	{
		if ((n[nElementCount - 1 - (r / blockSizeInBits)] >> r & 1) == 1)
		{
			break;
		}
		 
		else
		{
			r++;
		}
	}

	const short bitShiftRight = (r % blockSizeInBits);
	const short dLength = nElementCount - (r / blockSizeInBits);
	const BLOCKSIZEUSED rLSBmask = ByteMask >> (blockSizeInBits - bitShiftRight); // least significant r bits are 1
	BLOCKSIZEUSED rLSBs = 0;
	BLOCKSIZEUSED prevBlockrLSBs = 0;

	for (int i = 0; i < dLength; i++) // no need to shift some of the least signifcant blocks
	{	// shift the individual elements in the array and save to d
		prevBlockrLSBs = rLSBs << (blockSizeInBits - bitShiftRight);
		rLSBs = n[i] & rLSBmask;
		d[dElementCount - dLength + i] = n[i] >> bitShiftRight;
		d[dElementCount - dLength + i] |= prevBlockrLSBs;
	}

	n[nElementCount - 1] += 1; // 1 was subtracted for d now add 1 again because n has to be used as the modulus

	// a can be of a shorter length, especially now that they are vectors.
	std::vector<BLOCKSIZEUSED> a(nElementCount);
	std::vector<BLOCKSIZEUSED> aToThePowerOfd(nElementCount);
	std::vector<BLOCKSIZEUSED> greatestCommonDivisor(nElementCount);
	// this is needed to compare if it is the same as -1 since the data type for the blocks are unsigned values.
	std::vector<BLOCKSIZEUSED> aToThePowerOfdIncremented(nElementCount);

	for (int j = 0; j < k; j++)
	{
		std::memcpy(aToThePowerOfd.data(), zeroInBlocks.data(), blockSizeInBytes * nElementCount);

		randomNumSmallerThan(&a, nElementCount, n, nElementCount, lengthOfVectorOfBlock(n, nElementCount));
		gcd(a, nElementCount, n, nElementCount, &greatestCommonDivisor, nElementCount);

		while (greatestCommonDivisor[nElementCount -1] != 1 || lengthOfVectorOfBlock(greatestCommonDivisor, nElementCount) != 1)
		{
			std::memcpy(aToThePowerOfd.data(), zeroInBlocks.data(), blockSizeInBytes * nElementCount);
			randomNumSmallerThan(&a, nElementCount, n, nElementCount, lengthOfVectorOfBlock(n, nElementCount));
			
			gcd(a, nElementCount, n, nElementCount, &greatestCommonDivisor, nElementCount);
		}

		modularExponentiation(a, nElementCount, d, dElementCount, n, nElementCount, &aToThePowerOfd, nElementCount);

		addition(1, aToThePowerOfd, nElementCount, &aToThePowerOfdIncremented, nElementCount, nElementCount - 1);

		if (aToThePowerOfd[dLength - 1] == 1 && lengthOfVectorOfBlock(aToThePowerOfd, nElementCount) == 1)  // passes for this witness
		{
			continue;
		}

		else
		{
			for (int i = 0; i < r; i++)
			{
				if (compareVec(n, nElementCount, aToThePowerOfdIncremented, nElementCount) == 0) // passes for this witness
				{
					break;
				}

				else
				{
					shiftVector(d, dElementCount, &d, dElementCount, 0, 1, true); // probably will start with the 0th block anyway no need to add the overhead of calculating where to start for each block
					modularExponentiation(a, nElementCount, d, dElementCount, n, nElementCount, &aToThePowerOfd, nElementCount);
					addition(1, aToThePowerOfd, nElementCount, &aToThePowerOfdIncremented, nElementCount, nElementCount - 1);
				}
			}

			if (compareVec(n, nElementCount, aToThePowerOfdIncremented, nElementCount) == 0) // passes for this witness
			{
				continue;
			}

			else
			{
				return false;
			}
		}
	}

	return true;
}

void RSA::randomNumSmallerThan(std::vector<BLOCKSIZEUSED>* ptrToA, const int AelementCount, const std::vector<BLOCKSIZEUSED> X, const int XelementCount, const int Xlength)
{
	if(AelementCount != XelementCount)
	{
		throw std::runtime_error("A and C size do not match");
	}

	std::random_device rd;
	std::mt19937 gen(rd());

	int xStartIndex = XelementCount - Xlength;
	std::uniform_int_distribution<uint64_t> dist(0, ByteMask);
	std::uniform_int_distribution<uint64_t> smallerThanX0(1, X[xStartIndex]);

	std::vector<BLOCKSIZEUSED> A(AelementCount);

	A[xStartIndex] = smallerThanX0(gen);

	if (A[xStartIndex] == X[xStartIndex])
	{
		std::memcpy(ptrToA->data() + xStartIndex, A.data() + xStartIndex, blockSizeInBytes);
		randomNumSmallerThan(ptrToA, AelementCount, X, XelementCount, Xlength - 1);
	}

	else
	{
		for (int i = xStartIndex + 1; i < blockCount; i++)
		{
			A[i] = dist(gen);
		}

		std::memcpy(ptrToA->data() + xStartIndex, A.data() + xStartIndex, Xlength * blockSizeInBytes);
	}
}

int RSA::compareVec(std::vector<BLOCKSIZEUSED> X, const int XelementCount, std::vector<BLOCKSIZEUSED> Y, const int YelementCount)
{
	if(lengthOfVectorOfBlock(X, XelementCount) > lengthOfVectorOfBlock(Y, YelementCount))
		return 1;
	else if(lengthOfVectorOfBlock(X, XelementCount) < lengthOfVectorOfBlock(Y, YelementCount))
		return -1;

	for (int i = 0; i < XelementCount - 1; i++)
	{
		if (X[i] > Y[i])
			return 1;
		else if(X[i] < Y[i])
			return -1;
	}

	return 0;
}

void RSA::gcd(std::vector<BLOCKSIZEUSED> X, const int XelementCount, std::vector<BLOCKSIZEUSED> Y, const int YelementCount, std::vector<BLOCKSIZEUSED>* dst, const int dstElementCount)
{
	if(XelementCount != YelementCount)
		throw std::runtime_error("Wrong vectors for GCD");
	else if(XelementCount != dstElementCount)
		throw std::runtime_error("Wrong vectors for GCD");

	std::vector<BLOCKSIZEUSED> moddedResult(XelementCount);

 	modularFunctionForVectorOfBlocks(X, XelementCount, Y, YelementCount, &moddedResult, XelementCount);
	
	if (lengthOfVectorOfBlock(moddedResult, XelementCount) != 0)
	{
		gcd(Y, XelementCount, moddedResult, XelementCount, dst, XelementCount);
	}

	else
	{
		int startIndex = XelementCount - lengthOfVectorOfBlock(Y, XelementCount);
		std::memcpy(dst->data() + startIndex, Y.data() + startIndex, lengthOfVectorOfBlock(Y, XelementCount) * blockSizeInBytes);
	}
}

void RSA::randomNum(std::vector<BLOCKSIZEUSED>* X, const int XelementCount)
{
	std::random_device rd;
	std::mt19937 gen(rd());

	std::uniform_int_distribution<uint64_t> LSblock(2, ByteMask);
	std::uniform_int_distribution<uint64_t> dist(0, ByteMask);

	std::vector<BLOCKSIZEUSED> A(XelementCount);

	A[XelementCount - 1] = LSblock(gen);

	for (int i = 0; i < XelementCount - 1; i++)
	{
		A[i] = dist(gen);
	}

	std::memcpy(X->data(), A.data(), blockSizeInBytes * XelementCount);
}

int RSA::getStartIndex(std::vector<BLOCKSIZEUSED> X, int XelementCount)
{
	return 1;
}
