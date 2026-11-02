## Summary

`mini_query_get()` allocates exactly `value_len` bytes for the decoded value, then calls `mini_url_decode()` with `out_size = value_len`. When the value contains no escape sequence, the loop fills the whole buffer and the terminator in `src/url.c` line 28 writes one byte past the heap allocation:

```c
	out[n] = '\0';
```

## Proof of concept

```c
char *v = mini_query_get("id=AAAAAAAA", "id");
```

Built with `-fsanitize=address`, this reports a heap-buffer-overflow WRITE of size 1 in `mini_url_decode`.

## Impact

Any server that passes a client query string to `mini_query_get()` gets a one-byte heap overflow with a NUL byte, which can corrupt allocator metadata.
