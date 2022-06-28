#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "./metrohash-c/src/metrohash.h"

#define SEED 1337
#define ITEM_LENGTH 15
#define FINGERPRINT_BITS 27
#define FINGERPRINT_SIZE_IN_BYTES (((FINGERPRINT_BITS-1)/BITS_PER_BYTE) + 1)
#define FINGERPRINT_BITMASK (0x07FFFFFFUL)
#define ENTRIES_PER_BUCKET 4
#define HEADER_LENGTH_BYTES 8
#define BITS_PER_BYTE 8

typedef uint32_t fingerprint_t;
typedef uint64_t hash_t;
/*
    LITTLE-ENDIANNESS AND BIG-ENDIANNESS:
    The length of the filter is written in little-endian order (so C code can painlessly read it)
    The cuckoo filter itself is written in big-endian order

    Suppose we had the following 27 bit fingerprint to insert into our filter:
    0 0 0 0 0 1 1 1
    1 1 1 1 1 1 1 1
    1 1 1 1 1 1 1 1
    1 1 1 1 1 1 1 1

    With filter currently initialized as:
    [0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0] [0 0 0 0 0 0 0 0 0]

    We are effectively bitshifting the entire fingerprint to the left by 5, and doing an OR operation on the filter to get:
    [1 1 1 1 1 1 1 1] [1 1 1 1 1 1 1 1] [1 1 1 1 1 1 1 1] [1 1 1 0 0 0 0 0 0]

    This ended up being (for me) the more logical way to intuit how fingerprints should be ordered in a byte array
    (also I tried little-endian representation at first but it didn't work :/ )
*/

// inline is this magic word that ppl throw around saying that it improves performance when small functions are often called
// sounds useful, but no clue how to use (yet)

unsigned char *read_file(const char *filename, long *filelen)
{
  FILE *fileptr;
  unsigned char *buffer;
  long len;

  /*
   * Open the file in binary mode
   * Jump to the end of the file
   * Get the current byte offset in the file
   * Jump back to the beginning of the file
   */
  fileptr = fopen(filename, "rb");
  fseek(fileptr, 0, SEEK_END);
  len = ftell(fileptr);
  rewind(fileptr);

  buffer = (unsigned char *) malloc(len * sizeof(unsigned char));
  fread(buffer, len, 1, fileptr);
  fclose(fileptr);
  *filelen = len;
  return buffer;
}

/*
 * wrapper for the hash function in case we want to
 * swap it out with something else
 */
void hash_item(const uint8_t *item, uint32_t len, uint64_t *out)
{
    metrohash64_2(item, len, SEED, out);
}

/*
 * gets fingerprint at location
 */
int read_num_bits_from_byte_and_bit_offset(unsigned char *cf,
    uint64_t byte_offset, uint64_t bit_offset, fingerprint_t *target)
{
  int num_bytes_to_read = FINGERPRINT_SIZE_IN_BYTES;
  int remaining_bits = FINGERPRINT_BITS % BITS_PER_BYTE;

  int temp_bit_offset = bit_offset;
  /*
   * if fp spans 5 bytes, we need to offset the byte we're reading at by 1
   */
  int extra_byte = 0;

  uint8_t temporary_buffer[FINGERPRINT_SIZE_IN_BYTES];
  memset(temporary_buffer, 0, FINGERPRINT_SIZE_IN_BYTES);

  if (remaining_bits + bit_offset > BITS_PER_BYTE) {
      num_bytes_to_read += 1;
  }

  for (int i = 0; i < FINGERPRINT_SIZE_IN_BYTES; i++) {
    if (i == 0) { // byte 1
      if (temp_bit_offset + remaining_bits > BITS_PER_BYTE) {
        /*
         * read from two bytes
         */
        temporary_buffer[i] |= (unsigned char)(cf[byte_offset + i] <<
            temp_bit_offset) >> (BITS_PER_BYTE - remaining_bits);
        temporary_buffer[i] |= (unsigned char)cf[byte_offset + i + 1] >>
          (BITS_PER_BYTE - (remaining_bits + temp_bit_offset - BITS_PER_BYTE));
        temp_bit_offset += remaining_bits - BITS_PER_BYTE;
        extra_byte = 1;
      } else {
        /*
         * read from only 1 byte
         * first shift left by temp_bit_offset
         * then shift right by 5 (8 - remaining_bits)
         */
        temporary_buffer[i] |= (unsigned char)(cf[byte_offset + i] <<
            temp_bit_offset) >> (BITS_PER_BYTE - remaining_bits);
        temp_bit_offset += remaining_bits;
        temp_bit_offset = temp_bit_offset % BITS_PER_BYTE;
      }
    } else { // middle and end bytes
      if (temp_bit_offset == 0) {
        /*
         * read in single byte
         */
        temporary_buffer[i] |= (unsigned char)cf[byte_offset + i +
          extra_byte];
      } else {
        /*
         * read in from two bytes
         */
        temporary_buffer[i] |= (unsigned char)cf[byte_offset + i +
          extra_byte - 1] << temp_bit_offset;
        temporary_buffer[i] |= (unsigned char)cf[byte_offset + i +
          extra_byte] >> (BITS_PER_BYTE - temp_bit_offset);
      }
    }
  }

  /*
   * now temporary_buffer contains the fp we want in big endian order.
   * turn to uint32 now
   */
  *target = temporary_buffer[0] << 24 | temporary_buffer[1] << 16 |
    temporary_buffer[2] << 8 | temporary_buffer[3];

  return 1;
}

/*
 * get location in terms of byte, bit offset from index and bucket number
 */
int get_byte_and_bit_offset(uint64_t index, uint64_t entry_num,
    uint64_t *byte_offset, uint64_t *bit_offset)
{
  /*
   * note, the server side chunk header is discarded at network beacon
   * and the per-pkt header from the network beacon is discarded at the
   * dongle before passing the CF payload to lookup operations
   */
  uint64_t total_bits_from_begin = FINGERPRINT_BITS *
    (index * ENTRIES_PER_BUCKET + entry_num);

  *byte_offset = total_bits_from_begin / BITS_PER_BYTE;
  *bit_offset = total_bits_from_begin % BITS_PER_BYTE;

  return 1;
}

/*
 * returns 1 if fingerprint was found in bucket, 0 otherwise
 */
int match_on_index(unsigned char *cf, uint64_t index, fingerprint_t fp)
{
  for (uint64_t i = 0; i < ENTRIES_PER_BUCKET; i++) {
    uint64_t byte_offset = 0;
    uint64_t bit_offset = 0;
    get_byte_and_bit_offset(index, i, &byte_offset, &bit_offset);
    fingerprint_t fp_to_check = 0;
    read_num_bits_from_byte_and_bit_offset(cf, byte_offset, bit_offset,
        &fp_to_check);
//    printf("idx %ld bkt %ld byte %lu bit %lu fp 0x%08lx chk 0x%08lx\r\n",
//        (uint32_t) index, (uint32_t) i, (uint32_t) byte_offset,
//        (uint32_t) bit_offset, fp, fp_to_check);
    if (fp_to_check == fp)
      return 1; // match!
  }
  return 0; // not found
}

/*
 * gets fingerprint
 */
fingerprint_t get_fingerprint(hash_t hash)
{
  // uint64_t shifted = hash >> (64 - FINGERPRINT_BITS);
  fingerprint_t fp = (hash % (FINGERPRINT_BITMASK - 1)) + 1;
  return fp;
}

/*
 * gets two indices and fingerprint of item
 */
int get_index_and_fp(unsigned char item[], uint64_t num_buckets,
    uint64_t *i1, uint64_t *i2, fingerprint_t *fp)
{
  hash_t hash;
  hash_t doublehash;

  hash_item(item, ITEM_LENGTH, &hash);
  fingerprint_t computedFp = get_fingerprint(hash);
  uint8_t *p = (uint8_t *)&computedFp;
  uint8_t result[FINGERPRINT_SIZE_IN_BYTES];
  for(int i = 0; i < FINGERPRINT_SIZE_IN_BYTES; i++) {
      result[i] = p[i];
  }

  hash_item(result, FINGERPRINT_SIZE_IN_BYTES, &doublehash);

  uint64_t index1 = hash & (num_buckets - 1);
  uint64_t index2 = (index1 ^ doublehash) & (num_buckets - 1);
  memcpy(i1, &index1, BITS_PER_BYTE);
  memcpy(i2, &index2, BITS_PER_BYTE);
  memcpy(fp, &computedFp, FINGERPRINT_SIZE_IN_BYTES);

  return 1;
}

/*
 * looks up item in cuckoo filter. returns 1 if found, 0 if not
 */
int lookup(unsigned char *item, unsigned char *cf, uint64_t num_buckets)
{
  uint64_t index1 = 0;
  uint64_t index2 = 0;
  fingerprint_t fp = 0;
  get_index_and_fp(item, num_buckets, &index1, &index2, &fp);
  int result1 = match_on_index(cf, index1, fp);
  int result2 = match_on_index(cf, index2, fp);
  int result = result1 || result2;
//  printf("fp: 0x%08lx idx1: %ld idx2: %ld r1: %d r2: %d r: %d\r\n",
//    fp, (uint32_t) index1, (uint32_t) index2, result1, result2, result);
  return result;
}

/*
 * read first 8 bytes to get number of pointers
 */
void read_num_bytes_from_pointer(unsigned char *cf, uint64_t *num_bytes)
{
    memcpy(num_bytes, cf, sizeof(uint64_t));
    return;
}

/*
 * =================
 * TESTING PROECURES
 * =================
 */

int test_read_4_bytes()
{
  unsigned char all_ones[] = {0xFF, 0xFF, 0xFF, 0xFF}; // all 1's
  unsigned char alternating[] = {0xAA, 0xAA, 0xAA, 0xAA}; // alternating 1's and 0's
  unsigned char all_zeros[] = {0x00, 0x00, 0x00, 0x00}; // all 0's
  uint64_t byte_offset = 0;
  uint64_t bit_offset_0 = 0;
  fingerprint_t *target_bit_0_case_0 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(all_ones, byte_offset,
      bit_offset_0, target_bit_0_case_0);
  fingerprint_t *target_bit_0_case_1 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(alternating, byte_offset,
      bit_offset_0, target_bit_0_case_1);
  fingerprint_t *target_bit_0_case_2 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(all_zeros, byte_offset,
      bit_offset_0, target_bit_0_case_2);
  // do some assertions
  printf("Bit 0 case 0 expected value: %u, real value: %lu\n",
      134217727, *target_bit_0_case_0);
  printf("Bit 0 case 1 expected value: %u, real value: %lu\n",
      89478485, *target_bit_0_case_1);
  printf("Bit 0 case 2 expected value: %u, real value: %lu\n",
      0, *target_bit_0_case_2);


  uint64_t bit_offset_5 = 5;
  fingerprint_t *target_bit_5_case_0 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(all_ones, byte_offset,
      bit_offset_5, target_bit_5_case_0);
  fingerprint_t *target_bit_5_case_1 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(alternating, byte_offset,
      bit_offset_5, target_bit_5_case_1);
  fingerprint_t *target_bit_5_case_2 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(all_zeros, byte_offset,
      bit_offset_5, target_bit_5_case_2);
  // do some more assertions
  printf("Bit 5 case 0 expected value: %u, real value: %lu\n",
      134217727, *target_bit_5_case_0);
  printf("Bit 5 case 1 expected value: %u, real value: %lu\n",
      44739242, *target_bit_5_case_1);
  printf("Bit 5 case 2 expected value: %u, real value: %lu\n",
      0, *target_bit_5_case_2);
  return 0;
}

int test_read_5_bytes()
{
  unsigned char all_ones[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // all 1's
  unsigned char alternating[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA}; // alternating 1's and 0's
  unsigned char all_zeros[] = {0x00, 0x00, 0x00, 0x00, 0x00}; // all 0's
  uint64_t byte_offset = 0;
  uint64_t bit_offset_6 = 6;
  fingerprint_t *target_bit_6_case_0 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(all_ones, byte_offset,
      bit_offset_6, target_bit_6_case_0);
  fingerprint_t *target_bit_6_case_1 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(alternating, byte_offset,
      bit_offset_6, target_bit_6_case_1);
  fingerprint_t *target_bit_6_case_2 = malloc(sizeof(fingerprint_t));
  read_num_bits_from_byte_and_bit_offset(all_zeros, byte_offset,
      bit_offset_6, target_bit_6_case_2);
  printf("Bit 6 case 0 expected value: %u, real value: %lu\n",
      134217727, *target_bit_6_case_0);
  printf("Bit 6 case 1 expected value: %u, real value: %lu\n",
      89478485, *target_bit_6_case_1);
  printf("Bit 6 case 2 expected value: %u, real value: %lu\n",
      0, *target_bit_6_case_2);

  return 0;
}

int test_lookup(unsigned char *cf, uint64_t num_buckets)
{
  unsigned char item1[] =
    "\x88\xb4\x3e\x2f\xec\xc5\xa4\x99\x0e\x66\x62\xfb\x24\x69\x00";
  unsigned char item2[] =
    "\xb0\xbd\x44\x62\x12\x5c\xa1\xbf\x7a\x99\xf7\xa8\xec\x3e\x00";
  unsigned char item3[] =
    "\xb9\x22\xe2\xc0\xdc\x62\x49\x0e\x20\xc3\xf1\x41\x79\x8b\x00";

  unsigned char notanitem1[] = "blablablablabla";
  unsigned char notanitem2[] = "tralalalalalala";

  printf("Looking up item 1: %d\n", lookup(item1, cf, num_buckets));
  printf("Looking up item 2: %d\n", lookup(item2, cf, num_buckets));
  printf("Looking up item 3: %d\n", lookup(item3, cf, num_buckets));

  printf("Looking up false item 1: %d\n", lookup(notanitem1, cf, num_buckets));
  printf("Looking up false item 2: %d\n", lookup(notanitem2, cf, num_buckets));
  return 0;

}


/*
 * =============
 * API FUNCTIONS
 * =============
 */

#include "cf-gadget.h"

uint64_t cf_gadget_num_buckets(uint64_t num_bytes)
{
  return (num_bytes * 8) / (FINGERPRINT_BITS * ENTRIES_PER_BUCKET);
}

/*
 * =============
 * MAIN PROECURE
 * =============
 */

#ifdef MAIN
int main()
#else
int cf_gadget_main()
#endif
{

//	cf_t cf;

  // read file into buffer
  char const name[] = "test.bin";
  long *filelen = malloc(sizeof(long));
  void *buf = read_file(name, filelen);
  uint64_t num_bytes;

  // number of bytes to read from here on out
  read_num_bytes_from_pointer(buf, &num_bytes);

  uint64_t num_buckets = cf_gadget_num_buckets(num_bytes);
  test_lookup(buf, num_buckets);

  // test_read_4_bytes();
  // test_read_5_bytes();

  // calling test procedure to demonstrate lookup functionality
  // test(cf);

  // avoid memory leak
  free(filelen);
  free(buf);

  return 0;
}
