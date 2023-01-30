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



#' Item: Simple Password   `r lifecycle::badge('experimental')`
#'
#' Creator for simple password object types
#'
#' @param title     Object title. Will be used as identifier and file name.
#' @param url       URL to which it applies.
#' @param username  Username to store.
#' @param password  Password to store.
#'
#' @return  a `pass.simple` object.
#'
#' @examples
#' pw <- item_pass.simple("test_title", "test_url", "test_user", "my secret pass")
#' pw
#'
#' @export
item_pass.simple <- function(title, url = NULL, username = NULL, password = NULL) {

  if(is.null(username)) {
    message("Username is NULL. Proceed with caution.")
  }
  if(is.null(password)) {
    message("Password is NULL. Proceed with caution.")
  }
  class(password) <- "password"

  out <- list(title = title,
              url = url,
              username = username,
              password = password)

  class(out) <- c("pass.simple", "safevault.item")
  return(out)
}


#' @export
print.pass.simple <- function(x, ...) {
  cat("SafeVault Item (Pass Simple):", x$title)
}
