#' @keywords internal
"_PACKAGE"

## usethis namespace: start
#' @importFrom argon2 argon2_hash
#' @importFrom argon2 argon2_kdf
#' @importFrom argon2 blake2b
#' @importFrom argon2 raw_as_char
#' @importFrom DBI dbBind
#' @importFrom DBI dbClearResult
#' @importFrom DBI dbConnect
#' @importFrom DBI dbDisconnect
#' @importFrom DBI dbExecute
#' @importFrom DBI dbGetQuery
#' @importFrom DBI dbSendQuery
#' @importFrom DBI dbSendStatement
#' @importFrom lifecycle deprecated
#' @importFrom openssl askpass
#' @importFrom openssl decrypt_envelope
#' @importFrom openssl encrypt_envelope
#' @importFrom openssl read_key
#' @importFrom openssl read_pubkey
#' @importFrom openssl rsa_keygen
#' @importFrom openssl write_pem
#' @importFrom RSQLCipher dbChangeKey
#' @importFrom RSQLCipher SQLite
#' @importFrom utils tail
## usethis namespace: end
NULL


#' @export
print.password <- function(x, ...) {
  print("**********")
}

#' @export
print.cc_number <- function(x, ...) {
  print(paste0("**** ",
               paste0(tail(strsplit(x, "")[[1]], 4), collapse = "")))
}

#' @export
print.cc_ccv <- function(x, ...) {
  print("***")
}
