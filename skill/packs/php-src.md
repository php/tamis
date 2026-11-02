## php-src classification

The PHP security classification below comes from the [PHP Vulnerability Disclosure Policy](https://github.com/php/policies/blob/main/security-classification.rst), CC BY 4.0, condensed. It complements the repository `SECURITY.md`, which lists the issues commonly reported that are not security issues.

### Levels

- High: a third party can compromise any or most installations, execute arbitrary code, disable the system or read any file the PHP user can, on typical installations or in frequently used code (session, json, mysql, openssl) under common settings. It usually needs a CVE.
- Medium: the same potential, but it requires an extension that is not commonly used, a configuration used only in narrow circumstances, an old version of a third-party library, or code and patterns used infrequently. It usually has a CVE.
- Low: a theoretical compromise that common practice makes impractical, a problem in configuration or documentation that misleads users, an unauthorized action with no practical use, or an issue present only in unstable branches. It usually needs no CVE.
- Not a security issue: it needs obviously malicious code, malicious arguments to a function not meant for unsanitized values, uncommon actions on the server, privileges above the PHP user, debugging facilities such as xdebug or `var_dump`, settings not recommended for production such as errors displayed to the output, non-standard environment variables such as `USE_ZEND_ALLOC`, non-standard builds or platforms, code or settings known to be insecure, FFI, an `open_basedir` bypass, or the built-in web server.

### The attacker

The attacker is remote and only sends data: a request, a file the application processes, or values an application passes to a function meant to handle untrusted input. PHP offers no sandbox, so whoever runs PHP code already has the PHP user's rights, and `disable_functions` and `open_basedir` are not security boundaries. The script, input to `unserialize()` and the arguments a developer chooses are not attacker data.

A memory violation that needs malicious error handlers, destructors, `__toString()` functions or other user callbacks written to trigger it is not a security issue, even when the corruption is real. Ask whether a reasonable application would contain the reproducer and leave only data to the attacker.

### Checks before scoring

- Compare the faulty code on the source references. When only the development branch holds it, it is present only in an unstable branch.
- A crash or assertion that only fires on a debug build is a bug, not a security issue. A report under AddressSanitizer with the Zend allocator on is not a non-standard build, while one that needs `USE_ZEND_ALLOC=0` is.
- In a bundled third-party library, check that php-src reaches the faulty code at all.

### Calibration

Medium is the usual level for a real bug with some impact. High needs a demonstrated code execution or data exposure, or a denial of service on a default configuration of a common extension. Critical is rare.

The team's CVSS 4.0 vectors carry `AT:P`. A crash from remote data is `AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N`, rated medium, because FPM replaces the crashed worker. Exploitation that needs heap shaping is `AC:H`. A hang or unbounded CPU use from a request is `VA:H`.
