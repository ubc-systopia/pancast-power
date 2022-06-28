#ifndef CF_GADGET__H
#define CF_GADGET__H

#include <stdint.h>

typedef struct {

	void *buf;
	uint64_t num_buckets;

} cf_t;

int lookup(unsigned char* item, unsigned char* cf, uint64_t num_buckets);
uint64_t cf_gadget_num_buckets(uint64_t num_bytes);

#endif
