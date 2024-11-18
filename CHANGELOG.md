# RELEASE NOTES

## X.X.X (X X, X)

#### FEATURES/ENHANCEMENTS:

* Modified code to use `yaml.SafeLoader` to improve security when loading `yaml` configuration files.

## 2.0.1 (June 18, 2024)

#### FEATURES/ENHANCEMENTS:

* Updated various dependencies

## 2.0.0 (January 18, 2023)

#### BREAKING CHANGES:

* Default section is now `default`, was `cps`
* Update to v11 for:
  * create, update enrollment API call
  * accept to get enrollments

#### BUG FIXES:

* Fix case when listing enrollments didn't show updates on enrollment after having it cached
* Fix non recognizing `accountkey` option ([#48](https://github.com/akamai/cli-cps/issues/48))

#### FEATURES/ENHANCEMENTS:

* Added support for arm64
* Updated various dependencies
* Third party cert: status shows both ecsda and rsa csr
* Third party cert: proceed allows upload of signed ecdsa or rsa
* Update allows for --force-renewal (optional) argument