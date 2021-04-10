#include "helpers.h"
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <tox/tox.h>
#include <sodium/utils.h>

off_t file_size(const char *path)
{
    struct stat st;

    if (stat(path, &st) == -1) {
        return 0;
    }

    return st.st_size;
}

//taken from metidox
int save_data(Tox *m, const char *path)
{
    if (path == NULL) {
        goto on_error;
    }

    FILE *fp = fopen(path, "wb");

    if (fp == NULL) {
        return -1;
    }

    size_t data_len = tox_get_savedata_size(m);
    char *data = malloc(data_len);

    if (data == NULL) {
        goto on_error;
    }

    tox_get_savedata(m, (uint8_t *) data);
 if (fwrite(data, data_len, 1, fp) != 1) {
        free(data);
        fclose(fp);
        goto on_error;
    }

    free(data);
    fclose(fp);
    return 0;

on_error:
    fprintf(stderr, "Warning: save_data failed\n");
    return -1;
}

Tox *load_tox(struct Tox_Options *options, char *path)
{
   FILE *fp = fopen(path, "rb");
    Tox *m = NULL;

    if (fp == NULL) {
        TOX_ERR_NEW err;
        m = tox_new(options, &err);

        if (err != TOX_ERR_NEW_OK) {
            fprintf(stderr, "tox_new failed with error %d\n", err);
            return NULL;
        }

        save_data(m, path);
        return m;
    }

    off_t data_len = file_size(path);

    if (data_len == 0) {
        fclose(fp);
        return NULL;
    }

    char data[data_len];
    if (fread(data, sizeof(data), 1, fp) != 1) {
        fclose(fp);
        return NULL;
    }

    TOX_ERR_NEW err;
    options->savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options->savedata_data = (uint8_t *) data;
    options->savedata_length = data_len;

    m = tox_new(options, &err);

    if (err != TOX_ERR_NEW_OK) {
        fprintf(stderr, "tox_new failed with error %d\n", err);
        return NULL;
    }

    fclose(fp);
    return m;
}


typedef struct DHT_node {
  const char *ip;
  uint16_t port;
  const char key_hex[TOX_PUBLIC_KEY_SIZE*2 + 1];
  unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;


//TODO must be configured from xml
void bootstrap_DHT(Tox *tox) {
  DHT_node nodes[] =
    {
     { "185.25.116.107",     33445, "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43" }
,
     { "79.140.30.52",       33445, "FFAC871E85B1E1487F87AE7C76726AE0E60318A85F6A1669E04C47EB8DC7C72D" }
,
     { "46.101.197.175", 443, "CD133B521159541FB1D326DE9850F5E56A6C724B5B8E5EB5CD8D950408E95707" },
    };


  for (size_t i = 0; i < sizeof(nodes)/sizeof(DHT_node); i ++) {
    sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
                   nodes[i].key_hex, sizeof(nodes[i].key_hex)-1, NULL, NULL, NULL);
    tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, NULL);
  }
}

void hex2bin(unsigned char * const bin, const size_t bin_maxlen,
	     const char * const hex, const size_t hex_len) {
  sodium_hex2bin(bin, bin_maxlen,
		 hex, hex_len, NULL, NULL, NULL);
}
