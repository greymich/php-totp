<?php 
use PHPUnit\Framework\TestCase;
/**
*  Corresponding Class to test TOTP class
*
*  @author h.y.michael@icloud.com
*  @author michael@sunnyvision.com
*/
class TOTPTest extends TestCase
{
  public function testShouldBeTrue()
  {
      $this->assertTrue(true);
  }
  /**
  * check for syntax error 
  *
  */
  public function testShouldBeFreeOfSyntaxError()
  {
  	$otp = new Greymich\TOTP\TOTP;
  	$this->assertTrue(is_object($otp));
  	unset($otp);
  }

  public function testShouldEncodeAndDecodeBase32()
  {
    $sharedSecret = Greymich\TOTP\TOTP::base32Encode("12345678901234567890");
    $this->assertEquals(Greymich\TOTP\TOTP::base32Decode($sharedSecret), "12345678901234567890");
    $sharedSecret = Greymich\TOTP\TOTP::base32Encode("Some very long string");
    $this->assertEquals(Greymich\TOTP\TOTP::base32Decode($sharedSecret), "Some very long string");
  }

  /**
   * Test aginst common secret 12345678901234567890
   * please see https://tools.ietf.org/html/rfc6238 
   *
   * @return void
   * @author 
   **/
  public function testShouldGenerateTotpWithSha1()
  {
    $sharedSecretSha1 = Greymich\TOTP\TOTP::base32Encode('12345678901234567890'); // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    $sharedSecretSha256 = Greymich\TOTP\TOTP::base32Encode('12345678901234567890123456789012'); // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====
    $sharedSecretSha512 = Greymich\TOTP\TOTP::base32Encode('1234567890123456789012345678901234567890123456789012345678901234'); // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=
    $otp = new Greymich\TOTP\TOTP($sharedSecretSha1);
    $otp->setAlgorithm('sha1');
    $this->assertEquals($otp->get(8, 30, null, 59), '94287082');
    $this->assertEquals($otp->get(8, 30, null, 1111111109), '07081804');
    $this->assertEquals($otp->get(8, 30, null, 1111111111), '14050471');
    $this->assertEquals($otp->get(8, 30, null, 1234567890), '89005924');
    $this->assertEquals($otp->get(8, 30, null, 20000000000), '65353130');
    $this->assertEquals($otp->get(8, 30, null, 2000000000), '69279037');
    $otp = new Greymich\TOTP\TOTP($sharedSecretSha256);
    $otp->setAlgorithm('sha256');
    $this->assertEquals($otp->get(8, 30, null, 59), '46119246');
    $this->assertEquals($otp->get(8, 30, null, 1111111109), '68084774');
    $this->assertEquals($otp->get(8, 30, null, 1111111111), '67062674');
    $this->assertEquals($otp->get(8, 30, null, 1234567890), '91819424');
    $this->assertEquals($otp->get(8, 30, null, 20000000000), '77737706');
    $this->assertEquals($otp->get(8, 30, null, 2000000000), '90698825');
    $otp = new Greymich\TOTP\TOTP($sharedSecretSha512);
    $otp->setAlgorithm('sha512');
    $this->assertEquals($otp->get(8, 30, null, 59), '90693936');
    $this->assertEquals($otp->get(8, 30, null, 1111111109), '25091201');
    $this->assertEquals($otp->get(8, 30, null, 1111111111), '99943326');
    $this->assertEquals($otp->get(8, 30, null, 1234567890), '93441116');
    $this->assertEquals($otp->get(8, 30, null, 20000000000), '47863826');
    $this->assertEquals($otp->get(8, 30, null, 2000000000), '38618901');

  }

  /**
   * Test for otp url for google authenticator
   * please see https://tools.ietf.org/html/rfc6238 
   *
   * @return void
   * @author 
   **/
  public function testShouldGenerateGoogleAuthenticatorCompatibleUri()
  {
    $sharedSecret = Greymich\TOTP\TOTP::base32Encode("12345678901234567890");
    $otp = new Greymich\TOTP\TOTP($sharedSecret);
    $this->assertEquals(
      $otp->uri("[Platform] h.y.michael@icloud.com"), 
      "otpauth://totp/%5BPlatform%5D%20h.y.michael%40icloud.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    );
  }

}
