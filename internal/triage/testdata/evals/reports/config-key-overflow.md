## Summary

`mini_config_load()` in `src/config.c` copies everything before the `=` of a line into the 64-byte stack buffer `key` with no length check:

```c
		memcpy(key, line, eq - line);
```

A configuration line with a key longer than 64 bytes overflows the stack.

## Proof of concept

Write a configuration file whose single line is 200 `A` followed by `=1`, then call `mini_config_load()` on it. AddressSanitizer reports a stack-buffer-overflow.

## Impact

Stack buffer overflow, possibly code execution.
