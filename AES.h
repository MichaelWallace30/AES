#include <stdint.h>


namespace AES_NAMESPACE{

#define BLOCK_SIZE 16
#define MATRIX_SIZE 4 //sqrt(BLOCK_SIZE)

    class AES{

        AES();
        ~AES();

        uint32_t cypher(uint8_t *buffer, uint32_t size, uint8_t* key);
        

    private:

        uint8_t block[MATRIX_SIZE][MATRIX_SIZE];

        /** Sub Bytes **/

        /** Shift Rows **/
								void ShiftRows();

        /** Mix Columns 
            Galois Field matrix multiplication **/
                void mixColumns();

        /** Add Round Key **/

        


    };


};

