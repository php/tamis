## Summary

`mini_base64_decode()` in `src/base64.c` line 42 computes the output size as `len * 3 / 4` without rounding up, then writes the padding bytes past the end of the buffer:

```c
	out[olen++] = (char) (triple & 0xff);
```

## Proof of concept

```c
char out[3];
mini_base64_decode("QUJD", 4, out);
```

## Impact

Heap overflow reachable from any base64 input.
