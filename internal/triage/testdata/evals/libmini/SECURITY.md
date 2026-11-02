# Security policy

Report vulnerabilities through GitHub private vulnerability reporting.

libmini parses URL query strings from untrusted clients. It trusts its configuration files and the program that embeds it: a bug that needs a crafted configuration file passed to `mini_config_load()` is an ordinary bug, not a vulnerability, so please report it as a public issue.
