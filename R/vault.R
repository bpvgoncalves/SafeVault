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
init <- function(vault_path = NULL, key_size = 8192) {
  cat("Initializing Vault\n")

  if (is.null(vault_path)) stop("Invalid vault path.")

  key <- argon2::argon2_kdf(openssl::askpass("Please enter vault password:"))
  if (!identical(key,
                 argon2::argon2_kdf(openssl::askpass("Please confirm vault password:"),
                                    key$salt))) {
    stop("Passwords do not match!")
  }

  if (!dir.exists(vault_path)) {
    dir.create(vault_path)
    dir.create(paste0(vault_path, "/.meta"))
  } else {
    stop("Path already exists.")
  }

  salt <- key$salt
  saveRDS(salt, paste0(vault_path, "/.meta/slt"))
  rm(salt)

  cat("Creating keypair. This may take a while...\n")
  rsakey <- openssl::rsa_keygen(key_size)
  openssl::write_pem(rsakey,
                     paste0(vault_path, "/.meta/prv"),
                     password = paste0(key$key, collapse = ""))
  openssl::write_pem(rsakey$pubkey,
                     paste0(vault_path, "/.meta/pub"))
  rm(rsakey, key)
  return()
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

  keys$pub_key <- openssl::read_pubkey(paste0(vault_path, "/.meta/pub"))
  keys$salt <- readRDS(paste0(vault_path, "/.meta/slt"))

  read_vault <- function () {
    dir(vault_path, include.dirs = FALSE)
  }

  item_store <- function(item) {
    name <- item$title
    item <- openssl::encrypt_envelope(serialize(item, NULL),
                                      pubkey = keys$pub_key)
    saveRDS(item, file = paste0(vault_path, "/", name), compress = TRUE)
    return()
  }

  item_read <- function(name) {

    kdf <- argon2::argon2_kdf(openssl::askpass("Please enter vault password:"),
                              keys$salt)
    item <- readRDS(paste0(vault_path, "/", name))
    item <- openssl::decrypt_envelope(item$data,
                                      item$iv,
                                      item$session,
                                      paste0(vault_path, "/.meta/prv"),
                                      password = paste0(kdf$key, collapse = ""))
    rm(kdf)
    return(unserialize(item))
  }


  return(list(read_vault = read_vault,
              item_store = item_store,
              item_read = item_read))

}
