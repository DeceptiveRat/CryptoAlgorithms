#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define INTMSB 0x80000000
#define BLOCKSIZEINBYTES 4
#define BYTES_TO_ENCRYPT_AT_ONCE 3
#define MAXPLAINTEXTSIZE 120

/* RULES
 *
 * ``Changes when the bytes to encrypt at once changes``
 * p*q = n > m, where m < 2^8*3 = 2*24
 * if p > 2^12, q > 2^12
 * p*q = n > (2^12)^2 = 2^24
 * also, p*q = n < 2^32
 *
 * (1) Thus, 2^12 < p, q < 2^16
 *
 * gcd(e, (p-1)*(q-1)) == 1 for e to have a modular multiplicative inverse d
 * since e is prime, (p-1)*(q-1)%e!=0 means gcd(e, (p-1)*(q-1)) == 1
 *
 * (2) Thus, (p-1)*(q-1)%e != 0
 */

// nType >= primeType^2
typedef uint16_t primeType;
typedef uint32_t nType;
typedef uint16_t encryptionKeyType;
// range of bezout coefficient that becomes d is between -(p-1)*(q-1) + 1 and (p-1)*(q-1). Thus, decryptionKeyType has to be bigger than 2 times the range of nType. It is easier to limit the value of (p-1)*(q-1) to smaller than 2^31
typedef int32_t decryptionKeyType;
typedef uint32_t blockType;

struct publicKey
{
	//char owner[5];
	nType n;
	encryptionKeyType e;
};

void encrypt(const primeType e, const nType n, const unsigned char* source, unsigned char* dest);
void decrypt(const decryptionKeyType d, const nType n, const unsigned char* source, unsigned char* dest);
nType fastExponentiation(const blockType base, const decryptionKeyType exponent, const nType modulus);
nType extendedEuclideanAlgorithm(const nType a, const nType b, decryptionKeyType* x, decryptionKeyType* y);

int main()
{
	unsigned char usrText[MAXPLAINTEXTSIZE];
	printf("> ");
	scanf("%s", usrText);

	if(strlen(usrText)>(MAXPLAINTEXTSIZE/BLOCKSIZEINBYTES*BYTES_TO_ENCRYPT_AT_ONCE))
	{
		printf("Error: max length: %d\n", MAXPLAINTEXTSIZE/BLOCKSIZEINBYTES*BYTES_TO_ENCRYPT_AT_ONCE - 1);
		exit(-1);
	}

	unsigned char plainText[MAXPLAINTEXTSIZE];
	memset(plainText, 0, MAXPLAINTEXTSIZE);
	const primeType p = 22993;
	const primeType q = 37139;

	// move usrText into plainText, leaving 1 blank byte and filling 3 bytes from usrText
	for(int i = 0;i<MAXPLAINTEXTSIZE/BLOCKSIZEINBYTES;i++)
	{
		strncpy(plainText+1 + BLOCKSIZEINBYTES*i, usrText+BYTES_TO_ENCRYPT_AT_ONCE*i, BYTES_TO_ENCRYPT_AT_ONCE);
	}

	struct publicKey BobKey;
	BobKey.n = (nType)p*q;
	BobKey.e = 13;

	char* encryptedText = NULL;
	encryptedText = (char*)malloc(MAXPLAINTEXTSIZE);
	if(encryptedText  == NULL)
	{
		printf("Error while allocating memory\n");
		exit(0);
	}

	printf("\n");
	printf("p: %05d q: %05d\n", p, q);
	printf("e: %d\n", BobKey.e);
	printf("encrypting...\n");

	// encrypt
	for(int i = 0;i<MAXPLAINTEXTSIZE;i+=BLOCKSIZEINBYTES)
		encrypt(BobKey.e, BobKey.n, plainText+i, encryptedText+i);

	printf("Encrypted text in hexadecimal:\n");
	for(int i = 0;i<strlen(usrText)*BLOCKSIZEINBYTES/BYTES_TO_ENCRYPT_AT_ONCE;i++)
	{
		if(i%BLOCKSIZEINBYTES==0)
			continue;
		else
			printf("%02x", (unsigned char)encryptedText[i]);
	}
	printf("\n");
	
	// get decryption key
	decryptionKeyType d;
	decryptionKeyType x;
	nType result = extendedEuclideanAlgorithm((p-1)*(q-1), BobKey.e, &x, &d);

	if(d<0)
		d+=(p-1)*(q-1);

	if(result!= 1)
	{
		printf("gcd(%d, (%d-1)*(%d-1)) == %d != 1\n", BobKey.e, p, q, result);
		exit(0);
	}

	printf("\n");
	printf("d: %d\n", d);
	printf("decrypting...\n");
	printf("\n");

	char* decryptedText = NULL;
	decryptedText = (char*)malloc(MAXPLAINTEXTSIZE);
	if(decryptedText  == NULL)
	{
		printf("Error while allocating memory\n");
		exit(0);
	}

	// decrypt
	for(int i = 0;i<MAXPLAINTEXTSIZE;i+=BLOCKSIZEINBYTES)
		decrypt(d, BobKey.n, encryptedText+i, decryptedText+i);
	
	unsigned char decryptedPlainText[MAXPLAINTEXTSIZE];
	memset(decryptedPlainText, 0, MAXPLAINTEXTSIZE);
	// remove the empty first bytes
	for(int i = 0;i<MAXPLAINTEXTSIZE/BLOCKSIZEINBYTES;i++)
	{
		strncpy(decryptedPlainText+BYTES_TO_ENCRYPT_AT_ONCE*i, decryptedText+1+BLOCKSIZEINBYTES*i, BYTES_TO_ENCRYPT_AT_ONCE);
	}

	printf("Decrypted String is: %s\nOriginal text is: %s\n", decryptedPlainText, usrText);

	return 0;
}

void encrypt(const encryptionKeyType e, const nType n, const unsigned char* source, unsigned char* dest)
{
	blockType plainBlock = 0;
	blockType encryptedBlock;

	// store as little endian
	for(int i =0;i<BLOCKSIZEINBYTES;i++)
		plainBlock += (source[i]<<((BLOCKSIZEINBYTES-1-i)*8));

	encryptedBlock = fastExponentiation(plainBlock, e, n);

	// store as big endian in char
	for(int i = 0;i<BLOCKSIZEINBYTES;i++)
		dest[i] = (encryptedBlock>>((BLOCKSIZEINBYTES-1-i)*8))&0xff;
}

// almost the same as the encryption function
void decrypt(const decryptionKeyType d, const nType n, const unsigned char* source, unsigned char* dest)
{
	blockType encryptedBlock = 0;
	blockType decryptedBlock;

	for(int i =0;i<BLOCKSIZEINBYTES;i++)
		encryptedBlock += (source[i]<<((BLOCKSIZEINBYTES-1-i)*8));

	decryptedBlock = fastExponentiation(encryptedBlock, d, n);

	for(int i = 0;i<BLOCKSIZEINBYTES;i++)
		dest[i] = (decryptedBlock>>((BLOCKSIZEINBYTES-1-i)*8))&0xff;
}

nType fastExponentiation(const blockType base, const decryptionKeyType exponent, const nType modulus)
{
	uint64_t result = 1;

	// find first 1 bit in the exponent
	int startLocation = 0;
	while(((INTMSB >> startLocation) & exponent) == 0)
		startLocation++;

	for(int i = startLocation;i<32;i++)
	{
		result*=result;
		result%=modulus;

		if(((INTMSB >> i) & exponent) != 0)
		{
			result*=base;
			result%=modulus;
		}
	}

	return result;
}

/*
 * gcd(e, d) = a*x + b*y
 */
nType extendedEuclideanAlgorithm(const nType a, const nType b, decryptionKeyType* x, decryptionKeyType* y)
{
	if(b==0)
	{
		*x = 1;
		*y = 0;
		return a;
	}

	else
	{
		decryptionKeyType xPrime;
		decryptionKeyType yPrime;
		nType gcd = extendedEuclideanAlgorithm(b, a%b, &xPrime, &yPrime);
		*x = yPrime;
		*y = xPrime - (a/b)*yPrime;
		return gcd;
	}
}
