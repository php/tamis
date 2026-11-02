#include <stdlib.h>
#include <string.h>

#include "mini.h"

/* Returns the decoded value of key in an application/x-www-form-urlencoded query, or NULL. */
char *mini_query_get(const char *query, const char *key)
{
	size_t key_len = strlen(key);
	const char *p = query;

	while (p && *p) {
		const char *end = strchr(p, '&');
		size_t pair_len = end ? (size_t) (end - p) : strlen(p);

		if (pair_len > key_len && strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
			const char *value = p + key_len + 1;
			size_t value_len = pair_len - key_len - 1;
			char *out = malloc(value_len);

			if (!out) {
				return NULL;
			}
			mini_url_decode(value, value_len, out, value_len);
			return out;
		}
		p = end ? end + 1 : NULL;
	}

	return NULL;
}
