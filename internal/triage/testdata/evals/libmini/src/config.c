#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mini.h"

int mini_config_load(const char *path, struct mini_config *cfg)
{
	FILE *f = fopen(path, "r");
	char line[256];
	char key[64];

	if (!f) {
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *eq = strchr(line, '=');

		if (!eq) {
			continue;
		}
		memcpy(key, line, eq - line);
		key[eq - line] = '\0';
		if (strcmp(key, "name") == 0) {
			snprintf(cfg->name, sizeof(cfg->name), "%s", eq + 1);
		} else if (strcmp(key, "port") == 0) {
			cfg->port = atoi(eq + 1);
		}
	}
	fclose(f);

	return 0;
}
