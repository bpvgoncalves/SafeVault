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



#' Item: Credit Card   `r lifecycle::badge('experimental')`
#'
#' Creator for credit card object types
#'
#' @param title     Object title. Will be used as identifier.
#' @param number    Credit Card Number, number or string)
#' @param ccv       Credit Card CCV number, expected number or string.
#' @param expiry    Credit Card Expiry Date, an array of numbers labeled with 'y'(ear) and 'm'(onth)
#' @param owner     Credit Card owner, expected string or object of class 'person'.
#'
#' @return  a `card.credit` object.
#'
#' @examples
#' cc <- item_card.credit("CC - My Bank",
#'                        1234567890123456,
#'                        123,
#'                        c(m=1, y=2023),
#'                        person("Jane", "Doe"))
#'
#' # Prints CC object
#' cc
#'
#' # Prints CC number
#' cc$number
#'
#' # Prints CC ccv
#' cc$ccv
#'
#' # Prints CC expiry
#' cc$expiry
#'
#' # Prints CC owner
#' cc$owner
#'
#' @export
item_card.credit <- function(title, number, ccv, expiry = NULL, owner = NULL) {

  if(is.null(title))
    stop("'title' is required.")

  if (!(is.numeric(number) || is.character(number))) {
    stop("'number' has invalid data type.")
  } else if (is.numeric(number)) {
    number <- as.character(number)
  }
  class(number) <- "cc_number"

  if(!(is.numeric(ccv) || is.character(ccv))) {
    stop("'ccv' has invalid data type.")
  } else if(is.numeric(ccv)) {
    ccv <- as.character(ccv)
  }
  class(ccv) <- "cc_ccv"

  if(is.null(expiry)) {
    message("'expiry' is NULL. Proceed with caution.")
  } else if (length(expiry) != 2) {
    message("'expiry' is invalid and it will not be stored.")
    expiry <- NULL
  } else {
    n <- names(expiry) <- toupper(names(expiry))
    if (!("M" %in% n && "Y" %in% n)) {
      message("'expiry' has invalid names/labels and it will not be stored.")
      expiry <- NULL
    } else {
      expiry <- c(expiry["Y"], expiry["M"])
    }
  }

  if(is.null(owner))
    message("'owner' is NULL. Proceed with caution.")

  out <- list(title = title,
              number = number,
              expiry = expiry,
              ccv = ccv,
              owner = owner)

  class(out) <- c("card.credit", "safevault.item")
  return(out)
}


#' @export
print.card.credit <- function(x, ...) {
  cat("SafeVault Item (Credit Card):", x$title)
}
