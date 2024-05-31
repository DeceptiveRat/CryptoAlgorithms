#include <iostream>
#include <string>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <chrono>

#include "AES_Encryption.h"
#include "RSA.h"

int main()
{
    auto start = std::chrono::high_resolution_clock::now();

	std::array<RSA::BLOCKSIZEUSED, RSA::blockCount> test;
	std::array<RSA::BLOCKSIZEUSED, RSA::blockCount> a;
	std::array<RSA::BLOCKSIZEUSED, RSA::blockCount> result;

	for(int i = 0;i<300;++i)
	{
		RSA::randomNum(&test);	

		if(RSA::MillerRabinPrimalityTest(test))
		{
			for(int i = 0;i<RSA::blockCount;++i)
			{
				std::cout<<std::hex<<std::setw(8)<<std::setfill('0')<<test[i];
			}

			std::cout<<"\t is a prime!\n";
		}
		else
		{
			for(int i = 0;i<RSA::blockCount;++i)
			{
				std::cout<<std::hex<<std::setw(8)<<std::setfill('0')<<test[i];
			}

			std::cout<<"\t is not a prime!\n";
		}

		RSA::randomNum(&test);
	}


    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> duration = end - start;
    std::cout << "Execution time: " << duration.count() << " seconds\n";


// ========================================================= benchmark time =========================================================

    //auto start = std::chrono::high_resolution_clock::now();

    //auto end = std::chrono::high_resolution_clock::now();

    //std::chrono::duration<double> duration = end - start;
    //std::cout << "Execution time: " << duration.count() << " seconds\n";

// ==================================================================================================================================

    return 0;
}
