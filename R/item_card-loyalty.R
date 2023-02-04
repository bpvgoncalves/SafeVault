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



#' Item: Loyalty Card   `r lifecycle::badge('experimental')`
#'
#' Creator for loyalty card object types
#'
#' @param title     Object title. Will be used as identifier.
#' @param number    Loyalty Card Number, number or string)
#' @param expiry    Loyalty Card Expiry Date, an array of numbers labeled as 'y'(ear) and 'm'(onth)
#'
#' @return  a `card.loyalty` object.
#'
#' @examples
#' loyal <- item_card.loyalty("ABC Shop",
#'                            1234567890123456,
#'                            c(m=1, y=2023))
#'
#' # Prints LC object
#' loyal
#'
#' # Prints LC number
#' loyal$number
#'
#' # Prints LC expiry
#' loyal$expiry
#'
#' @export
item_card.loyalty <- function(title, number, expiry = NULL) {

  if(is.null(title))
    stop("'title' is required.")

  if (!(is.numeric(number) || is.character(number))) {
    stop("'number' has invalid data type.")
  } else if (is.numeric(number)) {
    number <- as.character(number)
  }
  class(number) <- "card_number"

  if (length(expiry) != 2) {
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

  out <- list(title = title,
              number = number,
              expiry = expiry)

  class(out) <- c("card.loyalty", "safevault.item")
  return(out)
}


#' @export
print.card.loyalty <- function(x, ...) {
  cat("SafeVault Item (Loyalty Card):", x$title)
}
