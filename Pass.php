<?php

namespace PHPAuthentication;

use ZxcvbnPhp\Zxcvbn;
use PHPMailer\PHPMailer\PHPMailer;

/**
 * Pass class
 * Required PHP 5.4 and above.
 */

class Pass
{

   /**
    * Initiates database connection
    */
   public function __construct( $config, $language = "en_GB")
   {
      $this->config = $config;

      // Load language
      require "languages/{$language}.php";
      $this->lang = $lang;
   }

   /**
   * Verifies that a password is valid and respects security requirements
   * @param string $password
   * @return array $return
   */
   public function validate($password) {
      $return['error'] = true;

      if (strlen($password) < (int)$this->config->password_min_length ) {
         $return['message'] = $this->lang["password_short"];
         return $return;
      }

      if (strlen($password) > (int)$this->config->password_max_length ) {
         $return['message'] = $this->lang["password_long"];
         return $return;
      }
      
      if( $this->config->password_strong_requirements )
      {
         $zxcvbn = new Zxcvbn();
   
         if ($zxcvbn->passwordStrength($password)['score'] < intval($this->config->password_min_score)) {
            $return['message'] = $this->lang['password_weak'];   
            return $return;
         }

      }

      $return['error'] = false;

      return $return;
   }

}// /class Pass