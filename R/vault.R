# SafeVault - Secure Data Storage
# Copyright (C) 2023  Bruno Gonçalves
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


#' New Vault Init   `r lifecycle::badge('experimental')`
#'
#' Initialize new vault
#'
#' @param vault_path   Path to vault file
#' @param key_size     Size for RSA key (Default: 8192 bits)
#'
#' @return NULL

#' @export
vault_init <- function(vault_path = NULL, key_size = 8192) {
  cat("Initializing Vault DB\n")

  if (is.null(vault_path))
    stop("Invalid vault path.")
  if (file.exists(vault_path))
    stop("File already exists. Try open a Vault Manager or change the path.")

  pass <- argon2::blake2b(openssl::askpass("Please enter vault password:"))
  if (!identical(pass,
                 argon2::blake2b(openssl::askpass("Please confirm vault password:")))) {
    stop("Passwords do not match!")
  }

  cat("Deriving symmetric keys and generating asymmetric key pair. Please be patient!\n")
  k <- keygen_full(pass, key_size)
  rm(pass)
  gc()

  db <- DBI::dbConnect(RSQLCipher::SQLite(), vault_path, key = k$keyDB$raw_hash)

  DBI::dbExecute(db,
                 "CREATE TABLE metadata (
                   md_key TEXT NOT NULL,
                   md_value TEXT NOT NULL,
                   CONSTRAINT metadata_PK PRIMARY KEY (md_key));")
  DBI::dbExecute(db,
                 "CREATE TABLE item (
                   item_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                   item_title TEXT NOT NULL,
                   item_type TEXT NOT NULL,
                   item BLOB NOT NULL);")

  q <- DBI::dbSendStatement(db,
                            "INSERT INTO metadata (md_key, md_value) VALUES (:k, :v);")

  DBI::dbBind(q, params = list(k = "salt",
                               v = openssl::base64_encode(k$keyRSA$salt)))

  DBI::dbBind(q, params = list(k = "prv",
                               v = openssl::write_pem(k$RSA,
                                                      NULL,
                                                      password = paste0(k$keyRSA$key,
                                                                        collapse = ""))))
  DBI::dbBind(q, params = list(k = "pub",
                               v = openssl::write_pem(k$RSA$pubkey,
                                                      NULL)))
  DBI::dbClearResult(q)
  DBI::dbDisconnect(db)
  rm(k, db, q)
  return(0)
}



#' Vault Manager   `r lifecycle::badge('experimental')`
#'
#' Manages the safe vault file
#'
#' @param vault_path  Path to vault file
#' @param strict      Boolean. If TRUE the password will be requested every time an item is read
#'  from the vault.
#'
#' @return
#' Vault Manager enclosure
#'
#' @export
vault_manager <- function(vault_path = NULL, strict = FALSE) {

  if (is.null(vault_path)) stop("Invalid vault path.")

  p <- argon2::blake2b(openssl::askpass("Please enter vault password:"))
  k <- keygen_keyDBonly(p)

  db <- DBI::dbConnect(RSQLCipher::SQLite(), vault_path, key = k$keyDB$raw_hash)

  keys <- new.env(TRUE, emptyenv())
  keys$salt <- openssl::base64_decode(DBI::dbGetQuery(db,
                                                      "SELECT md_value
                                                      FROM metadata
                                                      WHERE md_key='salt'")[[1]])
  keys$pub_key <- openssl::read_pubkey(DBI::dbGetQuery(db,
                                                       "SELECT md_value
                                                       FROM metadata
                                                       WHERE md_key='pub'")[[1]])
  if(!strict)
    keys$prv_key_k <- keygen_keyRSAonly(p, keys$salt)[[1]][[1]]
  else
    keys$prv_key_k <- NULL


  read_vault <- function () {
    DBI::dbGetQuery(db,
                    "SELECT item_title
                    FROM item")
  }

  close_vault <- function() {

    DBI::dbDisconnect(db)
  }

  change_key <- function() {

    op <- argon2::blake2b(openssl::askpass("Please enter OLD vault password:"))
    np <- argon2::blake2b(openssl::askpass("Please enter NEW vault password:"))
    if (!identical(np,
                   argon2::blake2b(openssl::askpass("Please confirm NEW vault password:")))) {
      stop("Passwords do not match!")
    }

    cat("Deriving new keys from password. Please be patient!\n")
    ok1 <- keygen_keyDBonly(op)[[1]][[1]]
    nk1 <- keygen_keyDBonly(np)[[1]][[1]]

    if (is.null(keys$prv_key_k)) {
      ok2 <- keygen_keyRSAonly(op, keys$salt)[[1]]
    } else {
      ok2 <- keys$prv_key_k
    }
    nk2 <- keygen_keyRSAonly(np, 32L)[[1]]
    rm(op, np)
    gc()

    # Change file encryption key
    RSQLCipher::dbChangeKey(db, ok1, nk1)
    rm(ok1, nk1)
    gc()

    # Change RSA key encryption
    q <- DBI::dbSendStatement(db,
                              "UPDATE metadata SET md_value=:v WHERE md_key=:k;")

    DBI::dbBind(q, params = list(k = "salt",
                                 v = openssl::base64_encode(nk2$salt)))
    keys$salt <- nk2$salt

    v <- openssl::write_pem(openssl::read_key(DBI::dbGetQuery(db,
                                                              "SELECT md_value
                                                              FROM metadata
                                                              WHERE md_key='prv'")[[1]],
                                              paste0(ok2, collapse = "")),
                            NULL,
                            password = paste0(nk2$key, collapse = ""))
    DBI::dbBind(q, params = list(k = "prv",
                                 v = v))
    if(!strict)
      keys$prv_key_k <- nk2$key
    rm(ok2, nk2)
    gc()

  }

  item_store <- function(item) {
    name <- item$title
    type <- class(item)[1]
    item <- openssl::encrypt_envelope(serialize(item, NULL),
                                      pubkey = keys$pub_key)

    q <- DBI::dbSendStatement(db,
                              "INSERT INTO item (item_title, item_type, item)
                              VALUES
                              (:ttl, :type, :item)")
    df <- data.frame(item = I(serialize(item, NULL)))
    DBI::dbBind(q, params = list(ttl = name,
                                 type = type,
                                 item = df))
    DBI::dbClearResult(q)
    rm(q, df, item)
    return(0)
  }

  item_read <- function(name) {

    q <- DBI::dbSendQuery(db,
                          "SELECT item
                          FROM item
                          WHERE item_title = :ttl;")
    DBI::dbBind(q, params = list(ttl = name))
    item <- unserialize(DBI::dbFetch(q)$item[[1]])
    DBI::dbClearResult(q)

    if (is.null(keys$prv_key_k)) {
      k <- keygen_keyRSAonly(argon2::blake2b(openssl::askpass("Please enter vault password:")),
                             keys$salt)
    } else {
      k <- keys$prv_key_k
    }

    item <- openssl::decrypt_envelope(item$data,
                                      item$iv,
                                      item$session,
                                      DBI::dbGetQuery(db,
                                                      "SELECT md_value
                                                       FROM metadata
                                                       WHERE md_key='prv'")[[1]],
                                      password = paste0(k, collapse = ""))
    rm(q, k)
    return(unserialize(item))
  }


  return(list(read_vault = read_vault,
              close_vault = close_vault,
              # change_key = change_key,
              item_store = item_store,
              item_read = item_read))

}
