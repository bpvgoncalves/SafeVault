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
#' @param vault_path   Path to vault folder
#' @param key_size     Size for RSA private key (Default: 8192)
#'
#' @return NULL

#' @export
vault_init <- function(vault_path = NULL, key_size = 8192) {
  cat("Initializing Vault DB\n")

  if (is.null(vault_path)) stop("Invalid vault path.")
  if (!file.exists(vault_path)) {
    db <- DBI::dbConnect(RSQLite::SQLite(), vault_path)
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
  } else {
    stop("Path already exists. Try open a Vault Manager or change the path.")
  }

  cat("Deriving key from password. Please be patient!\n")
  key <- argon2::argon2_kdf(openssl::askpass("Please enter vault password:"))
  if (!identical(key,
                 argon2::argon2_kdf(openssl::askpass("Please confirm vault password:"),
                                    key$salt))) {
    stop("Passwords do not match!")
  }

  q <- DBI::dbSendStatement(db, "INSERT INTO metadata (md_key, md_value) VALUES (:k, :v);")
  DBI::dbBind(q, params = list(k = "salt",
                               v = openssl::base64_encode(key$salt)))

  cat("Creating keypair. This may take a while...\n")
  rsakey <- openssl::rsa_keygen(key_size)
  DBI::dbBind(q, params = list(k = "prv",
                               v = openssl::write_pem(rsakey,
                                                      NULL,
                                                      password = paste0(key$key, collapse = ""))))
  DBI::dbBind(q, params = list(k = "pub",
                               v = openssl::write_pem(rsakey$pubkey,
                                                      NULL)))
  DBI::dbClearResult(q)
  DBI::dbDisconnect(db)
  rm(rsakey, key, db, q)
  return(0)
}



#' Vault Manager   `r lifecycle::badge('experimental')`
#'
#' Manages the safe vault folder
#'
#' @param vault_path  Path to vault folder
#'
#' @return
#' Vault Manager enclosure
#'
#' @export
vault_manager <- function(vault_path = NULL) {

  if (is.null(vault_path)) stop("Invalid vault path.")

  keys <- new.env(TRUE, emptyenv())

  db <- DBI::dbConnect(RSQLite::SQLite(), vault_path)

  keys$salt <- openssl::base64_decode(DBI::dbGetQuery(db,
                                                      "SELECT md_value
                                                      FROM metadata
                                                      WHERE md_key='salt'")[[1]])
  keys$pub_key <- openssl::read_pubkey(DBI::dbGetQuery(db,
                                                       "SELECT md_value
                                                       FROM metadata
                                                       WHERE md_key='pub'")[[1]])


  read_vault <- function () {
    DBI::dbGetQuery(db,
                    "SELECT item_title
                    FROM item")
  }

  close_vault <- function() {

    DBI::dbDisconnect(db)
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
    DBI::dbBind(q, params = list(ttl = "name",
                                 type = type,
                                 item = df))
    DBI::dbClearResult(q)
    rm(q, df, item)
    return(0)
  }

  item_read <- function(name) {

    kdf <- argon2::argon2_kdf(openssl::askpass("Please enter vault password:"),
                              keys$salt)
    q <- DBI::dbSendQuery(db,
                          "SELECT item
                          FROM item
                          WHERE item_title = :ttl;")
    DBI::dbBind(q, params = list(ttl = name))
    item <- unserialize(DBI::dbFetch(q)$item[[1]])
    item <- openssl::decrypt_envelope(item$data,
                                      item$iv,
                                      item$session,
                                      DBI::dbGetQuery(db,
                                                      "SELECT md_value
                                                       FROM metadata
                                                       WHERE md_key='prv'")[[1]],
                                      password = paste0(kdf$key, collapse = ""))
    DBI::dbClearResult(q)
    rm(q, kdf)
    return(unserialize(item))
  }


  return(list(read_vault = read_vault,
              close_vault = close_vault,
              item_store = item_store,
              item_read = item_read))

}
