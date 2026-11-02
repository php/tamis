#include <ctype.h>

#include "mini.h"

static int hex_value(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	return tolower((unsigned char) c) - 'a' + 10;
}

/* Decodes the %XX escapes and the '+' of a URL query component, and NUL-terminates the result. */
size_t mini_url_decode(const char *in, size_t len, char *out, size_t out_size)
{
	size_t n = 0;

	for (size_t i = 0; i < len && n < out_size; i++) {
		if (in[i] == '+') {
			out[n++] = ' ';
		} else if (in[i] == '%' && i + 2 < len && isxdigit((unsigned char) in[i + 1]) && isxdigit((unsigned char) in[i + 2])) {
			out[n++] = (char) (hex_value(in[i + 1]) * 16 + hex_value(in[i + 2]));
			i += 2;
		} else {
			out[n++] = in[i];
		}
	}
	out[n] = '\0';

	return n;
}
