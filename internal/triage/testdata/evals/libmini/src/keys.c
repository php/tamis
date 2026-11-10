#include <string.h>

#include "mini.h"

/* Stores a pointer to each pair of an application/x-www-form-urlencoded query in keys, and returns their count. */
size_t mini_query_keys(const char *query, const char **keys, size_t max)
{
	size_t n = 0;
	const char *p = query;

	while (p && *p) {
		const char *end = strchr(p, '&');

		keys[n++] = p;
		p = end ? end + 1 : NULL;
	}

	return n;
}
