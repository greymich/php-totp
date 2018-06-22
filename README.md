PHP TOTP
=========================

This library is an implementation of totp (rfc6238) in php (currently only sha1)

Features
--------

* PSR-4 autoloading compliant structure
* Unit-Testing with PHPUnit
* Easy to use to any framework or even a plain php file
* Supports SHA1 of HOTPTimeBased

Installation
---

Using composer (recommended):
```
$ composer require greymich/php-totp
```

In separate package:
```
require "path/to/lib/src/TOTP.php"
```


Examples
---

To start randomize a base32 secret or create one from an ASCII string
```
// ASCII to base32
$secret = Greymich\TOTP\TOTP::base32Encode("12345678901234567890");
// Random
$secret = Greymich\TOTP\TOTP::genSecret(32);
// Initiate totp instance by secret
$otp = new Greymich\TOTP\TOTP($secret);
```


Validate an OTP
```
$userInput = "<get from input>";
$secret = "<get from database>";
$otp = new Greymich\TOTP\TOTP($secret);
// To mitigate possible timing attacks
if(hash_equals( $otp->get(), $userInput )) {
	// Correct
}
```

Generate OTP registration uri (For QR scanning)
```
$secret = Greymich\TOTP\TOTP::base32Encode("12345678901234567890");
$otp = new Greymich\TOTP\TOTP($secret);
$uri = $otp->uri("[Platform] h.y.michael@icloud.com");
```


Tests
---
```
composer test
```

```
TOTP
 ✔ Should be true
 ✔ Should be free of syntax error
 ✔ Should encode and decode base 32
 ✔ Should generate totp with sha 1
 ✔ Should generate google authenticator compatible uri
```

Test are run against SHA1 of rfc6238 suggested testing vectors
```
  +-------------+--------------+------------------+----------+--------+
  |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
  +-------------+--------------+------------------+----------+--------+
  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
  |             |   11:33:20   |                  |          |        |
  +-------------+--------------+------------------+----------+--------+
 ```