#include "AES.h"
#include <algorithm>

using namespace AES_NAMESPACE;


uint32_t AES::cypher(uint8_t *buffer, uint32_t size, uint8_t* key
{
    //check if block size if %16
    //either pad or throw error
}

void ShiftRows() {
		/**
		Iterate through rows of matrix starting at row 1
		*/
		for (int y = 1; y < MATRIX_SIZE; y++) {
				/*
				Move elements between index 0 and y to the end of the array, shifts
				elements that are being replaced towards the beginning of the array
				*/
				std::rotate(&block[y][0], &block[y][y], &block[y][MATRIX_SIZE]);
		}
}