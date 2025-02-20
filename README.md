# phpcs-security-sniffs

phpcs-security-sniffs is a collection of security-focused sniffs for
[PHP_CodeSniffer](https://github.com/PHPCSStandards/PHP_CodeSniffer/).
These sniffs will report security vulnerabilities in your PHP code.

This project is inspired
by [phpcs-security-audit](https://github.com/FloeDesignTechnologies/phpcs-security-audit),
a similar but no longer maintained project.

## Usage

Run PHP_CodeSniffer with the `Security` standard:

```sh
vendor/bin/phpcs --standard=Security /path/to/code
```

Example output:

```text
FILE: /path/to/file.php
-----------------------------------------------------------------------------------------------------------------------
FOUND 6 ERRORS AFFECTING 5 LINES
-----------------------------------------------------------------------------------------------------------------------
  5 | ERROR | Passing user input to require_once() can lead to remote file inclusion (CWE-98)
  9 | ERROR | Passing user input to shell_exec() can lead to OS command injection (CWE-78)
 11 | ERROR | Outputting unsanitized user input can lead to cross-site scripting (CWE-79)
 11 | ERROR | Passing user input to file_get_contents() can lead to path traversal attacks (CWE-22)
 13 | ERROR | Cleartext transmission of data over HTTP is a security risk (CWE-319)
 15 | ERROR | The sha1 algorithm is not safe for password hashing (CWE-916), use password_hash() for hashing passwords
-----------------------------------------------------------------------------------------------------------------------
```
