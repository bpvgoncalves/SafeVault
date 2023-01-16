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


#' New Vault Init
#' `r lifecycle::badge('experimental')`
#'
#' Initialize new vault
#'
#' @param vault_path   Path to vault folder
#' @param key_size     Size for RSA private key (Default: 8192)
#'
#' @return NULL

#' @export
#'

init <- function(vault_path = NULL, key_size = 8192) {
  cat("Initializing Vault\n")

  if (is.null(vault_path)) stop("Invalid vault path.")

  # TODO: Use proper key derivation
  # TODO: Use password salt
  pass <- openssl::sha512(askpass::askpass("Please enter vault password:"))
  if (pass != openssl::sha512(askpass::askpass("Please confirm vault password:"))) {
    stop("Passwords do not match!")
  }

  if (!dir.exists(vault_path)) {
    dir.create(vault_path)
    dir.create(paste0(vault_path, "/.meta"))
  } else {
    stop("Path already exists.")
  }

  cat("Creating keypair. This may take a while...\n")
  key <- openssl::rsa_keygen(key_size)
  openssl::write_pem(key, paste0(vault_path, "/.meta/prv"), password = pass)
  openssl::write_pem(key$pubkey, paste0(vault_path, "/.meta/pub"))
  rm(key, pass)
  return()
}



vault_manager <- function(vault_path = NULL) {

  if (is.null(vault_path)) stop("Invalid vault path.")

  pub_key <- openssl::read_pubkey(paste0(vault_path, "/.meta/pub"))[[1]]

  read_vault <- function () {
    dir(vault_path, include.dirs = FALSE)
  }

  item_store <- function(item) {
    name <- item$title
    item <- openssl::encrypt_envelope(serialize(item, NULL),
                                      pubkey = pub_key)
    saveRDS(item, file = paste0(vault_path, "/", name), compress = TRUE)
    return()
  }

  item_read <- function(name) {

    item <- readRDS(paste0(vault_path, "/", name))

    psw <- openssl::sha512(askpass::askpass("Please enter vault password:"))
    item <- openssl::decrypt_envelope(item$data,
                                      item$iv,
                                      item$session,
                                      openssl::read_key(paste0(vault_path, "/.meta/prv"), psw),
                                      psw)
    rm(psw)
    unserialize(item)
  }


  return(list(read_vault = read_vault,
              item_store = item_store))

}
