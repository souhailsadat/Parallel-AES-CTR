%%cu
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#define NB_THREADS 2

#define CTR 1

#define AES128 1
///#define AES192 1
///#define AES256 1

/// Block length in bytes - AES is 128b block only
#define AES_BLOCKLEN 16

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   /// Key length in bytes
    #define AES_keyExpSize 176
#endif

/*****************************************************************************/
/** Defines:                                                                  */
/*****************************************************************************/
/// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        /// The number of 32 bit words in a key.
    #define Nr 10       /// The number of rounds in AES Cipher.
#endif

/// jcallan@github points out that declaring Multiply as a function
/// reduces code size considerably with the Keil ARM compiler.
/// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif



struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
  uint8_t Iv[AES_BLOCKLEN];
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

/// Same function for encrypting as for decrypting.
/// IV is incremented for every block, and used after encryption as XOR-compliment for output
/// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
/// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
///        no IV should ever be reused with the same key
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

static void phex(uint8_t* str);
static int function_encrypt_ctr(const char* xcrypt);


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
/// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];



/// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
/// The numbers below can be computed dynamically trading ROM for RAM -
/// This can be useful in (embedded) bootloader applications, where ROM is often limited.
__device__ static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };


/// The round constant word array, Rcon[i], contains the values given by
/// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
__device__ static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 *
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed),
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

#define getSBoxValue(num) (sbox[(num)])

/// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}


/// This function adds the round key to state.
/// The round key is added to the state by an XOR function.
__device__ static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

/// The SubBytes Function Substitutes the values in the
/// state matrix with values in an S-box.
__device__ static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

/// The ShiftRows() function shifts the rows in the state to the left.
/// Each row is shifted with different offset.
/// Offset = Row number. So the first row is not shifted.
__device__ static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

__device__ static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

/// MixColumns function mixes the columns of the state matrix
__device__ static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

/// Multiply is used to multiply numbers in the field GF(2^8)
/// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
///       The compiler seems to be able to vectorize the operation better this way.
///       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
__device__ static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif



/// Cipher is the main function that encrypts the PlainText.
__device__ static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  /// Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  /// There will be Nr rounds.
  /// The first Nr-1 rounds are identical.
  /// These Nr rounds are executed in the loop below.
  /// Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  /// Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}



/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

__device__ int roundUp(int numToRound, int multiple)
{
    if (multiple == 0)
        return numToRound;

    int remainder = numToRound % multiple;
    if (remainder == 0)
        return numToRound;

    return numToRound + multiple - remainder;
}


/** Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key **/
__global__ void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t *length)
{
  int bi=0,cpt=0;
  uint8_t buffer[16];
  size_t i;
  struct AES_ctx myctx;
  int istart=0, iend=0, id=threadIdx.x;///cas où les threads appartiennet au même bloc
  istart=roundUp(id*((*length)/NB_THREADS),16);
  iend=roundUp((id+1)*((*length)/NB_THREADS),16);
  memcpy(myctx.Iv, ctx->Iv, 16);
  memcpy(myctx.RoundKey, ctx->RoundKey, AES_keyExpSize);
  bi = 16;
  for(i=0;i<(istart)/16;i++)
  {
	 for (bi = (16 - 1); bi >= 0; --bi)
	 {
	   /** inc will overflow **/
	   if (myctx.Iv[bi] == 255)
	   {
	       myctx.Iv[bi] = 0;
               continue;
	   }
	   myctx.Iv[bi] += 1;
	   break;
	 }
	 bi = 0;
  }
  bi = 16;
  for (i = istart; i < iend; ++i)
  {
    if (bi == 16) /** we need to regen xor compliment in buffer **/
    {
      memcpy(buffer, myctx.Iv, 16);
      Cipher((state_t*)buffer,myctx.RoundKey);

      /** Increment Iv and handle overflow **/
      for (bi = (16 - 1); bi >= 0; --bi)
      {
	    /** inc will overflow **/
        if (myctx.Iv[bi] == 255)
	    {
          myctx.Iv[bi] = 0;
          continue;
        }
        myctx.Iv[bi] += 1;
        break;
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
    ++bi;
  }
}




int main(void)
{
    int exit;

#if defined(AES256)
    printf("\n Testing : AES256 - Thread number : %d\n\n",NB_THREADS);
#elif defined(AES192)
    printf("\n Testing : AES192 - Thread number : %d\n\n",NB_THREADS);
#elif defined(AES128)
    printf("\n Testing : AES128 - Thread number : %d\n\n",NB_THREADS);
#else
    printf(" You need to specify a symbol between AES128, AES192 or AES256. Exiting");
    return 0;
#endif

    exit=function_encrypt_ctr("encrypt");
    printf("\n ");
    system("Pause");
    return exit;
}


/// prints string as hex
static void phex(uint8_t* str)
{

#if defined(AES256)
    uint8_t len = 32;
#elif defined(AES192)
    uint8_t len = 24;
#elif defined(AES128)
    uint8_t len = 16;
#endif

    unsigned char i;
    for (i = 0; i < len; ++i)
        printf(" %.2x", str[i]);
    printf("\n");
}



static int function_encrypt_ctr(const char* xcrypt)
{
#if defined(AES256)
    uint8_t key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t inp[64]  = { 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };
#elif defined(AES192)
    uint8_t key[24] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t inp[64]  = { 0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b,
                        0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef, 0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94,
                        0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70, 0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7,
                        0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58, 0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50 };
#elif defined(AES128)
    uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t inp[64]  = { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
                        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
                        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
                        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee };
#endif
    uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    uint8_t out[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx;
    uint8_t i;
    size_t taille=64;
    
    FILE *entrFichPtr;
    char nomFichEntr[255];
    FILE *resFichPtr;
    char nomFichSort[255];

    entrFichPtr=fopen("/content/drive/MyDrive/HPC/512MB.zip","rb");
    ///entrFichPtr=fopen(nomFichEntr,"rb");

    if(entrFichPtr==NULL)
    {
      printf(" Cannot open input file\n");
      exit(1);
    }
    ///Trouver la taille du fichier ouvert
    fseek(entrFichPtr, 0L, SEEK_END);///aller à la fin pour pouvoir déduire la taille à partir du dernier index (Offset)
    size_t fileLen = ftell(entrFichPtr);
    rewind(entrFichPtr);///Revenir au début du fichier
  
    printf("\n Input file size : %ld MB.\n",fileLen/(1024*1024));

    uint8_t *bufEntr = (uint8_t *) malloc(fileLen*sizeof(uint8_t));///Allouer assez de mémoire pour le fichier

    fread(bufEntr, fileLen, 1, entrFichPtr); ///Lire tout le fichier

    fclose(entrFichPtr);///fermer le fichier
  
    struct AES_ctx *gpu_ctx;
    uint8_t *gpu_inp;
    size_t *gpu_taille;
    uint8_t *gpu_RoundKey;
    uint8_t *gpu_Iv;
    cudaEvent_t start, stop;
    float elapsedTime;

    cudaMalloc ((void **) &gpu_inp, fileLen*sizeof(uint8_t));
    cudaMalloc ((void **) &gpu_RoundKey, AES_keyExpSize*sizeof(uint8_t));
    cudaMalloc ((void **) &gpu_Iv, AES_BLOCKLEN*sizeof(uint8_t));
    cudaMalloc ((void **) &gpu_ctx, sizeof(*gpu_ctx));
    cudaMalloc ((void **) &gpu_taille, sizeof(size_t));

    AES_init_ctx_iv(&ctx, key, iv);
 
    cudaMemcpy (gpu_inp, bufEntr, fileLen*sizeof(uint8_t), cudaMemcpyHostToDevice); 
    cudaMemcpy (gpu_RoundKey, ctx.RoundKey, AES_keyExpSize*sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy (gpu_Iv, ctx.Iv, AES_BLOCKLEN*sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy (gpu_taille, &fileLen, sizeof(size_t), cudaMemcpyHostToDevice);
    
    cudaMemcpy (gpu_ctx->RoundKey, gpu_RoundKey, AES_keyExpSize*sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy (gpu_ctx->Iv, gpu_Iv, AES_BLOCKLEN*sizeof(uint8_t), cudaMemcpyHostToDevice);   
    
    printf("\n input file (first 4 blocks) :\n");
    for (i = (uint8_t) 0; i < (uint8_t) 4; ++i)
    {
        phex(bufEntr + i * (uint8_t) 16);
    }
 
    
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
 
    cudaEventRecord(start,0);
     
 
    AES_CTR_xcrypt_buffer <<<1, NB_THREADS>>> (gpu_ctx, gpu_inp, gpu_taille);

    cudaEventRecord(stop,0);
    cudaEventSynchronize(stop);
 
    cudaEventElapsedTime(&elapsedTime, start,stop);

    cudaMemcpy (bufEntr, gpu_inp, fileLen*sizeof(uint8_t), cudaMemcpyDeviceToHost);

 
    cudaFree(gpu_inp);
    cudaFree(gpu_ctx);
    cudaFree(gpu_RoundKey);
    cudaFree(gpu_Iv);
    cudaFree(gpu_taille);
 
    printf("\n output file (first 4 blocks) :\n");
    for (i = (uint8_t) 0; i < (uint8_t) 4; ++i)
    {
        phex(bufEntr + i * (uint8_t) 16);
    }
    printf("\n Elapsed time : %f seconds\n" ,elapsedTime/1000);
    ///Ecrire le résultat du cryptage dans le flux de sortie
    /*resFichPtr=fopen("/content/drive/MyDrive/Colab Notebooks/outCuda.bin","wb");
    if(resFichPtr==NULL)
    {
      printf(" Cannot open output file\n");
      exit(1);
    }
    fwrite(bufEntr,1,fileLen, resFichPtr);
    fclose(resFichPtr);*/
 
    return 0;

}