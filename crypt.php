<?php

function encodeChecksum(string $message) {
  $sum = 0;
  for ($i = 0; $i < strlen($message); $i++) {
    $sum += ord($message[$i]);
  }
  $prefix = chr($sum % 255);
  return $prefix . $message;
}

function encrypt($data, $password) {  
  $method = 'aes-256-cbc';
  $password = substr(hash('sha256', $password, true), 0, 32);
  $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
  $data = encodeChecksum($data);
  $encrypted = base64_encode(openssl_encrypt($data, $method, $password, OPENSSL_RAW_DATA, $iv));
  return $encrypted;
}


function decodeChecksum(string $message) {
  if (strlen($message) < 2) {
    return false; // Not enough data to contain checksum and message
  }
  $checksumChar = $message[0];
  $actualMessage = substr($message, 1);
  $sum = 0;
  for ($i = 0; $i < strlen($actualMessage); $i++) {
    $sum += ord($actualMessage[$i]);
  }
  $expectedChecksum = chr($sum % 255);
  if ($checksumChar === $expectedChecksum) {
    return $actualMessage;
  } else {
    return false;
  }
}

function decrypt($encryptedData, $password) {
  $method = 'aes-256-cbc';
  $password = substr(hash('sha256', $password, true), 0, 32);
  $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
  $decrypted = openssl_decrypt(base64_decode($encryptedData), $method, $password, OPENSSL_RAW_DATA, $iv);
  $decrypted = decodeChecksum($decrypted);
  return $decrypted;
}
