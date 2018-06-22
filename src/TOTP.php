<?php
namespace Greymich\TOTP;

/**
 * TOTP implementation according to rfc6238
 *
 * @package Greymich\TOTP
 * @author h.y.michael@icloud.com
 * @author michael@sunnyvision.com
 **/
class TOTP
{

  public $secret = "";
  private $algorithm = 'sha1';
  private $supportedAlgorithms = ['sha1'];
  private static $base32Map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  public function __construct($secret = "") {
    $this->secret = $secret;
  }

  public function setAlgorithm($algorithm = 'sha1') {
    $algorithm = strtolower($algorithm);
    if(array_search($algorithm, $this->supportedAlgorithms)) {
      $this->algorithm = $algorithm;
      return true;
    }
    return false;
  }

  private static function timeServerTimeDiff() {
    // ntp time servers to contact
    // we try them one at a time if the previous failed (failover)
    // if all fail then wait till tomorrow
    $time_servers = array(
      "time.nist.gov",
      "nist1.datum.com",
      "time-a.timefreq.bldrdoc.gov",
      "utcnist.colorado.edu");
    $ts_count = count($time_servers);
    for ($i=0; $i<count($time_servers); $i++) {
      $time_server = $time_servers[$i];
      $fp = fsockopen($time_server, 37, $errno, $errstr, 30);
      if (!$fp) {
        echo "$time_server: $errstr ($errno)\n";
        echo "Trying next available server...\n\n";
      } else {
        $data = NULL;
        while (!feof($fp)) {
          $data .= fgets($fp, 128);
        }
        fclose($fp);

        if (strlen($data) != 4) {
          echo "NTP Server {$time_server} returned an invalid response.\n";
          if ($i != ($ts_count - 1)) {
            echo "Trying next available server...\n\n";
          } else {
            echo "Time server list exhausted\n";
          }
        } else {
          $valid_response = true;
          break;
        }
      }
    }

    if ($valid_response) {
      $NTPtime = ord($data{0})*pow(256, 3) + ord($data{1})*pow(256, 2) + ord($data{2})*256 + ord($data{3});

      $TimeFrom1990 = $NTPtime - 2840140800;
      $TimeNow = $TimeFrom1990 + 631152000;
      return time() - $TimeNow;
    } else {
      echo "The system time could not be updated. No time servers available.\n";
    }
  }

  public static function base32Decode( $in )
  {
    if (empty($in)) {
        return "";
    }
    $l = strlen( $in );
    $n = $bs = 0;
    for( $i = 0; $i < $l; $i++ )
    {
      $n <<= 5;
      $n += stripos( self::$base32Map, $in[$i] );
      $bs = ( $bs + 5 ) % 8;
      @$out .= $bs < 5 ? chr( ($n & (255 << $bs)) >> $bs ) : null;
    }
    return $out;
  }
  public static function base32Encode($data)
  {
      if (empty($data)) {
          return "";
      }
      if (is_integer($data)) {
          $binary = decbin($data);
          if ($modulus = strlen($binary) % 5) {
              $padding = 5 - $modulus;
              $binary = str_pad($binary, strlen($binary) + $padding, "0", STR_PAD_LEFT);
          }
      } else {
          $data = str_split($data);
          $binary = implode("", array_map(function ($character) {
              return sprintf("%08b", ord($character));
          }, $data));
      }
      $binary = str_split($binary, 5);
      $last = array_pop($binary);
      $binary[] = str_pad($last, 5, "0", STR_PAD_RIGHT);
      $encoded = implode("", array_map(function ($fivebits) {
          $index = bindec($fivebits);
          return self::$base32Map[$index];
      }, $binary));
      return $encoded;
  }

  public function get( $digits = 6, $period = 30, $offset = null, $now = null )
  {
    if($now === null) $now = time();
    $secret = $this->secret;
    if( strlen($secret) < 16 || strlen($secret) % 8 != 0 )
      throw new \Exception('secret length must >= 16 || %8==0');
    if( preg_match('/[^a-z2-7]/i', $secret) === 1 )
      throw new \Exception('sercret must be of base32');
    if( $digits < 6 || $digits > 8 )
      throw new \Exception('digits must be from 6 to 8');
    $seed = self::base32Decode( $secret );
    if($this->algorithm === 'sha256' && strlen($seed) < 32) {
      throw new \Exception('seed length must >= 32');
    }
    if($this->algorithm === 'sha512' && strlen($seed) < 64) {
      throw new \Exception('seed length must >= 64');
    }
    $time = str_pad( pack('N', intval($now / $period) + $offset ), 8, "\x00", STR_PAD_LEFT );
    $hash = hash_hmac( $this->algorithm, $time, $seed, false );
    $otp = ( hexdec(substr($hash, hexdec($hash[39]) * 2, 8)) & 0x7fffffff ) % pow( 10, $digits );
    return sprintf("%'0{$digits}u", $otp);
  }

  public static function genSecret( $length = 32 )
  {
    if( $length < 16 || $length % 8 != 0 )
      throw new \Exception('length must >= 16 || %8==0');
    while( $length-- )
    {
      $c = @gettimeofday()['usec'] % 53;
      while( $c-- )
        mt_rand();
      @$secret .= self::$base32Map[mt_rand(0, 31)];
    }
    return $secret;
  }

  public function uri( $account, $digits = null, $period = null, $issuer = null )
  {

    $secret = $this->secret;
    if( empty($account) || empty($secret) )
      throw new \Exception('account / secret must be provided');
    if( mb_strpos($account . $issuer, ':') !== false )
      throw new \Exception('cannot have colon in account / issuer');
    $account = rawurlencode( $account );
    $issuer = rawurlencode( $issuer );
    $label = empty( $issuer ) ? $account : "$issuer:$account";
    return 'otpauth://totp/' . $label . "?secret=$secret" .
    (is_null($digits) ? '' : "&digits=$digits") .
    (is_null($period) ? '' : "&period=$period") .
    (empty($issuer) ? '' : "&issuer=$issuer");
  }
}
?>