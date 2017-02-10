#include "AES.h"
#include <algorithm>

using namespace AES_NAMESPACE;

AES::AES()
{
    
}

AES::~AES()
{
    
}

uint32_t AES::cypher(uint8_t *buffer, uint32_t size, uint8_t* key)
{
    //check if block size if %16
    //either pad or throw error
}

void AES::SubBytes(uint8_t *buffer) {
    for(int i = 0; i < MATRIX_SIZE; ++i) {
        for(int j = 0; j < MATRIX_SIZE; ++j) {
          block[j][i] = buffer;
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