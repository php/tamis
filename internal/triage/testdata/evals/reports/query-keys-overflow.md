## Summary

`mini_query_keys()` in `src/keys.c` stores one pointer per `&`-separated pair into the caller's `keys` array and never compares the count with `max`:

```c
		keys[n++] = p;
```

A query string with more pairs than `max` writes pointers past the end of the array.

## Proof of concept

```c
const char *keys[4];
mini_query_keys("a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8", keys, 4);
```

Built with `-fsanitize=address`, this reports a stack-buffer-overflow WRITE in `mini_query_keys`.

## Impact

Any server that lists the keys of a client query string gets an out-of-bounds write of pointers the client positions.
