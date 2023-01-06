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
  private $supportedAlgorithms = ['sha1', 'sha256', 'sha512'];
  private static $base32Map = array('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','2','3','4','5','6','7', '=');
  private static $base32MapFlipped = array('A'=>'0', 'B'=>'1', 'C'=>'2', 'D'=>'3', 'E'=>'4', 'F'=>'5', 'G'=>'6', 'H'=>'7',
                                    'I'=>'8', 'J'=>'9', 'K'=>'10', 'L'=>'11', 'M'=>'12', 'N'=>'13', 'O'=>'14', 'P'=>'15',
                                    'Q'=>'16', 'R'=>'17', 'S'=>'18', 'T'=>'19', 'U'=>'20', 'V'=>'21', 'W'=>'22', 'X'=>'23',
                                    'Y'=>'24', 'Z'=>'25', '2'=>'26', '3'=>'27', '4'=>'28', '5'=>'29', '6'=>'30', '7'=>'31'
                                    );

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
      $NTPtime = ord($data[0])*pow(256, 3) + ord($data[1])*pow(256, 2) + ord($data[2])*256 + ord($data[3]);

      $TimeFrom1990 = $NTPtime - 2840140800;
      $TimeNow = $TimeFrom1990 + 631152000;
      return time() - $TimeNow;
    } else {
      echo "The system time could not be updated. No time servers available.\n";
    }
  }

  public static function base32Decode( $in )
  {
    if(empty($in)) return;
    $paddingCharCount = substr_count($in, self::$base32Map[32]);
    $allowedValues = array(6,4,3,1,0);
    if(!in_array($paddingCharCount, $allowedValues)) return false;
    for($i=0; $i<4; $i++){ 
        if($paddingCharCount == $allowedValues[$i] && 
            substr($in, -($allowedValues[$i])) != str_repeat(self::$base32Map[32], $allowedValues[$i])) return false;
    }
    $input = str_replace('=','', $in);
    $input = str_split($input);
    $binaryString = "";
    for($i=0; $i < count($input); $i = $i+8) {
        $x = "";
        if(!in_array($input[$i], self::$base32Map)) return false;
        for($j=0; $j < 8; $j++) {
            $x .= str_pad(base_convert(@self::$base32MapFlipped[@$input[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
        }
        $eightBits = str_split($x, 8);
        for($z = 0; $z < count($eightBits); $z++) {
            $binaryString .= ( ($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48 ) ? $y:"";
        }
    }
    return $binaryString;
  }

  public static function base32Encode($data)
  {
        if(empty($data)) return "";
        $input = str_split($data);
        $binaryString = "";
        for($i = 0; $i < count($input); $i++) {
            $binaryString .= str_pad(base_convert(ord($input[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
        }
        $fiveBitBinaryArray = str_split($binaryString, 5);
        $base32 = "";
        $i=0;
        while($i < count($fiveBitBinaryArray)) {    
            $base32 .= self::$base32Map[base_convert(str_pad($fiveBitBinaryArray[$i], 5,'0'), 2, 10)];
            $i++;
        }
        if($x = strlen($binaryString) % 40) {
            if($x == 8) $base32 .= str_repeat(self::$base32Map[32], 6);
            else if($x == 16) $base32 .= str_repeat(self::$base32Map[32], 4);
            else if($x == 24) $base32 .= str_repeat(self::$base32Map[32], 3);
            else if($x == 32) $base32 .= self::$base32Map[32];
        }
        return $base32;
  }

  public function get( $digits = 6, $period = 30, $offset = null, $now = null )
  {
    if($now === null) $now = time();
    $secret = $this->secret;
    if( strlen($secret) < 16 || strlen($secret) % 8 != 0 )
      throw new \Exception('secret length must >= 16 || %8==0');
    if( preg_match('/#^(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$#/i', $secret) === 1 )
      throw new \Exception('secret must be of base32');
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
    $offset = hexdec(substr($hash, strlen($hash) - 1)) & 0xF;
    $hash = array_map('hexdec', str_split($hash, 2));
    $otp = ((($hash[$offset] & 0x7f) << 24) |
             (($hash[$offset + 1] & 0xff) << 16) |
             (($hash[$offset + 2] & 0xff) << 8) |
             ($hash[$offset + 3] & 0xff)) % pow( 10, $digits );
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
      @$secret .= self::$base32Map[mt_rand(0, count(self::$base32Map) - 1)];
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
    return 'otpauth://totp/' . $label . "?algorithm=" . $this->algorithm .
    (is_null($digits) ? '' : "&digits=$digits") .
    (empty($issuer) ? '' : "&issuer=$issuer") .
    (is_null($period) ? '' : "&period=$period") .
    "&secret=$secret";
  }
}

