
keygen_full <- function(pass, rsa_len) {

  # Key to protect database file
  keyDB <- keygen_keyDBonly(pass)[[1]]

  # Key to protect rsa private key
  keyRSA <- keygen_keyRSAonly(pass, 32L)[[1]]

  # RSA certificate
  rsakey <- openssl::rsa_keygen(rsa_len)

  return(list(keyDB = keyDB,
              keyRSA = keyRSA,
              RSA = rsakey))
}


keygen_keyDBonly <- function(pass) {

  # Key to protect database file
  keyDB <- argon2::argon2_hash(argon2::raw_as_char(pass),
                               "SafeVaultSalt",
                               len = 32,
                               as_raw = FALSE)

  return(list(keyDB = keyDB))
}

keygen_keyRSAonly <- function(pass, salt) {

  # Key to protect rsa private key
  keyRSA <- argon2::argon2_kdf(argon2::raw_as_char(pass), salt)

  return(list(keyRSA = keyRSA))
}
