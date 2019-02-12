# Unreleased changes

* Support for `-p` and `-R` patch options in series file.

# Version 0.5.2

* Support for running analyses while patching.
* Added MultiApply analysis that warns when hunk could apply to more than one location.
* Fixed two kinds of panic when rolling-back failed patches.
* More information is shown when patch fails to apply.

# Version 0.5.1

* Fix detection of misordered hunks
* More changes for better compatibility with patch
* Added --verbose, --quiet and --version parameters

# Version 0.5.0

* Support for patches that change file permissions
* Use the same logic as patch does when choosing which file to patch
* Behave same as patch in various cornercases

# Version 0.4.3

* Faster patch parsing
* Support quoted filenames

# Version 0.4.2

* Bugfix: Prevent fail if there is date in patch file.

# Version 0.4.1

* Improved error and application failure reporting.
* Empty directories are deleted after deleting files.

# Version 0.4.0

* Added support for file-renaming patches.

# Version 0.3.0

* Added "--backup always|onfail|never" option.
* Added "--backup-count 0|<n>" option. Defaults to 100.
* Added "--fuzz <n>" option. Defaults to 0.
* Compatibility with various patch file format oddities.

# Version 0.2.0

First useable version.
