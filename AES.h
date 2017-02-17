#include <stdint.h>


namespace AES_NAMESPACE {

#define SBOX_SIZE 16
#define BLOCK_SIZE 16
#define MATRIX_SIZE 4 //sqrt(BLOCK_SIZE)

    /**
      Superman-box...
    */
    extern const uint8_t S_BOX[SBOX_SIZE][SBOX_SIZE];

    /**
      Inverse Superman-box. low quality. 
    */
		extern const uint8_t INVERSE_S_BOX[SBOX_SIZE][SBOX_SIZE];

    class AES {
    public:
        AES();
        ~AES();

        uint32_t encrypt(uint8_t *buffer, uint32_t size, uint8_t* key);
        
        /* Testing print method*/
        void debugPrint();

    //private:

        uint8_t block[MATRIX_SIZE][MATRIX_SIZE];

        /**
          Passes in the Sbox and inverts it. Contents stored 
          in output which must take in a 2D array param.
        */
        void GenerateInverseSBox(uint8_t sBox[SBOX_SIZE][SBOX_SIZE], 
          uint8_t output[SBOX_SIZE][SBOX_SIZE]);

        /* input transform method*/
        void SubBytes(uint8_t *buffer);

        /** Sub Bytes **/        
        void SBox();

			  void InverseSBox();

        /** Shift Rows **/
        void ShiftRows();

        void InverseShiftRows();

        /** Mix Columns
        Galois Field matrix multiplication **/
        void mixColumns(uint8_t *stateColumn);

        /** Add Round Key **/
        /*
         TODO(): Implemented Round Key!! 
        */

    };


};

