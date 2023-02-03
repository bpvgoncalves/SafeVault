
<!-- README.md is generated from README.Rmd. Please edit that file -->

# SafeVault

<!-- badges: start -->

[![Lifecycle:
experimental](https://img.shields.io/badge/lifecycle-experimental-orange.svg)](https://lifecycle.r-lib.org/articles/stages.html#experimental)
[![R-CMD-check](https://github.com/bpvgoncalves/SafeVault/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/bpvgoncalves/SafeVault/actions/workflows/R-CMD-check.yaml)
![GitHub](https://img.shields.io/github/license/bpvgoncalves/SafeVault?color=black)
![GitHub R package
version](https://img.shields.io/github/r-package/v/bpvgoncalves/SafeVault?color=black&label=Version%20GitHub)

<!-- badges: end -->

SafeVault is aimed at secure storage of data. It started as a way to
store passwords locally, but it can be used to store several types of
items.

Some helper functions are included to allow creation and processing of
specific types of items such as password or credit card information, but
anything that can be created or loaded into R can potentially be stored
inside the vault.

## Installation

You can install the development version of SafeVault like so:

``` r
# install.packages("devtools")

# Install dependencies
devtools::install_github("bpvgoncalves/argon2")
devtools::install_github("bpvgoncalves/RSQLCipher")

# Install main pacakage
devtools::install_github("bpvgoncalves/SafeVault")
```
