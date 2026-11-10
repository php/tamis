#ifndef MINI_H
#define MINI_H

#include <stddef.h>

struct mini_config {
	char name[64];
	int port;
};

size_t mini_url_decode(const char *in, size_t len, char *out, size_t out_size);
char *mini_query_get(const char *query, const char *key);
size_t mini_query_keys(const char *query, const char **keys, size_t max);
int mini_config_load(const char *path, struct mini_config *cfg);

#endif
