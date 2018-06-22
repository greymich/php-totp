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
    $sharedSecret = Greymich\TOTP\TOTP::base32Encode("12345678901234567890");
    $otp = new Greymich\TOTP\TOTP($sharedSecret);
    $this->assertEquals($otp->get(8, 30, null, 59), "94287082");
    $this->assertEquals($otp->get(8, 30, null, 1111111109), "07081804");
    $this->assertEquals($otp->get(8, 30, null, 1111111111), "14050471");
    $this->assertEquals($otp->get(8, 30, null, 1234567890), "89005924");
    $this->assertEquals($otp->get(8, 30, null, 2000000000), "69279037");
    $this->assertEquals($otp->get(8, 30, null, 20000000000), "65353130");
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
