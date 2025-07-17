# RELEASE NOTES

## 2.0.5 (Jul 17, 2025)

### FEATURES/ENHANCEMENTS:

* Updated various dependencies.

## 2.0.4 (May 23, 2025)

### FEATURES/ENHANCEMENTS:

* Updated various dependencies.

## 2.0.3 (Apr 16, 2025)

### FEATURES/ENHANCEMENTS:

* Unified exit codes to return `1` in all erroneous situations and corrected error messages.
* Updated various dependencies.

## 2.0.2 (Dec 10, 2024)

### FEATURES/ENHANCEMENTS:

* Modified code to use `yaml.SafeLoader` to improve security when loading `yaml` configuration files.
* Updated various dependencies.

## 2.0.1 (Jun 18, 2024)

### FEATURES/ENHANCEMENTS:

* Updated various dependencies.

## 2.0.0 (Jan 18, 2023)

### BREAKING CHANGES:

* Changed default section from `cps` to `default`.
* Updated to v11 for:
  * create, update enrollment API call
  * accept to get enrollments

### FEATURES/ENHANCEMENTS:

* Added support for arm64.
* Updated various dependencies.
* Third party cert: modified `status` to show both ecsda and rsa csr.
* Third party cert: modified `proceed` to allow upload of signed ecdsa or rsa.
* Added support for `--force-renewal` (optional) argument for updates.

### BUG FIXES:

* Fixed a case when listing enrollments didn't show updates on enrollment after having it cached.
* Fixed a non-recognizing `accountkey` option ([#48](https://github.com/akamai/cli-cps/issues/48)).