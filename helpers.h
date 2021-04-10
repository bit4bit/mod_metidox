#ifndef HELPERS_H
#define HELPERS_H

#include <tox/tox.h>

Tox *load_tox(struct Tox_Options *options, char *path);
int save_data(Tox *m, const char *path);
void bootstrap_DHT(Tox *tox);
void hex2bin(unsigned char * const bin, const size_t bin_maxlen,
	     const char * const hex, const size_t hex_len);
#endif /*HELPERS_H*/
