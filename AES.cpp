#include "AES.h"
#include <algorithm>

using namespace AES_NAMESPACE;

AES::AES()
{
    
}

AES::~AES()
{
    
}

uint32_t AES::encrypt(uint8_t *buffer, uint32_t size, uint8_t* key)
{
    //check if block size if %16
    //either pad or throw error
    return 0;
}

void AES::debugPrint()
{
    printf("\n");
    for (int x = 0; x < 4; x++)
    {
        for (int y = 0; y < 4; y++)
        {
            printf("%#04x ", block[x][y]);
        }
        printf("\n");
    }
}

uint8_t[SBOX_SIZE, SBOX_SIZE] AES::GenerateInverseSBox(uint8_t sBox[SBOX_SIZE][SBOX_SIZE])
{
		uint8_t inverseSBox[SBOX_SIZE][SBOX_SIZE];
		for (int i = 0; i < SBOX_SIZE; i++) {
				for (int j = 0; j < SBOX_SIZE; j++) {
						uint8_t val = sBox[i][j];
						uint8_t x = (val >> 4) & 0x0f;
						uint8_t y = val & 0x0f;
						uint8_t pos = (j & 0x0f);
						pos |= (i & 0x0f) << 4;
						inverseSBox[x][y] = pos;
				}
		}
		return inverseSBox;
}

void AES::SubBytes(uint8_t *buffer) {
    
    for(int i = 0; i < MATRIX_SIZE; ++i) {
        for(int j = 0; j < MATRIX_SIZE; ++j) {
          block[j][i] = buffer[i * MATRIX_SIZE + j];
        }
    }  
}


void AES::SBox() 
{
    uint8_t x_coord = 0, y_coord = 0; // x & y coord of the Rijndael S-Box
    for (int i = 0; i < MATRIX_SIZE; i++) {
        for (int j = 0; j < MATRIX_SIZE; j++) {
            x_coord = (block[i][j] & 0xf0) >> 4; // upper 4 bits
            y_coord = block[i][j] & 0x0f; // lower 4 bits
            block[i][j] = S_BOX[x_coord][y_coord];
        }
    }
}

void AES::InverseSBox()
{
		for (int i = 0; i < MATRIX_SIZE; i++) {
				for (int j = 0; j < MATRIX_SIZE; j++) {
						uint8_t x = (block[i][j] & 0xf0) >> 4;
						uint8_t y = (block[i][j] & 0x0f);
						block[i][k] = INVERSE_S_BOX[x][y];
				}
		}
}

void AES::ShiftRows() {
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

void AES::InverseShiftRows() {
		/**
		Iterate through rows of matrix starting at row 1
		*/
		for (int y = 1; y < MATRIX_SIZE; y++) {
				/**
				Move elements between the end of the array and end of the array - y to
				the beginning of the array
				*/
				std::rotate(std::reverse_iterator<uint8_t*>(std::end(block[y])),
						std::reverse_iterator<uint8_t*>(std::end(block[y])) + y,
						std::reverse_iterator<uint8_t*>(block[y]));
		}
}

/**
 * performs the mix column step of AES
 * @param stateColumn column of the state key to be mixed
 */
void AES::mixColumns(uint8_t *stateColumn) {
    uint8_t col1[4];//for the parts that are only being multiplied by 1
    uint8_t colAdj[4];//for the parts being multiplied by 2 or 3
    uint8_t t;//for storing the leftmost bit
    /**
    * Iterating through the state column, copying it to col1. The values from col1 are
    * multiplied by 2 and stored in colAdj and conditionally xored by 0x1b.
    */
    for (int c = 0; c < 4; c++) {
        col1[c] = stateColumn[c];
        t = stateColumn[c] >> 7;
        colAdj[c] = stateColumn[c] << 1 ^ 0x1b & t;
    }
    /**
    * Values multiplies by 2 and 3 are taken from coldAdj. Values multiplied by 1
    * are taken from col1. An extra value is added in for the valued multiplied by 3
    */
    stateColumn[0] = colAdj[0] ^ colAdj[1] ^ col1[1] ^ col1[2] ^ col1[3];
    stateColumn[1] = colAdj[1] ^ colAdj[2] ^ col1[2] ^ col1[0] ^ col1[3];
    stateColumn[2] = colAdj[2] ^ colAdj[3] ^ col1[3] ^ col1[0] ^ col1[1];
    stateColumn[3] = colAdj[3] ^ colAdj[0] ^ col1[0] ^ col1[1] ^ col1[2];
}