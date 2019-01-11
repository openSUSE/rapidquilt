# Rapidquilt

This is experimental and currently very limited reimplementation of quilt & patch in one.

The goal is to be very fast.


## Usage

    Usage: rapidquilt push [<options>] [num|patch]

    Options:
        -a, --all           apply all patches in series

        -d, --directory DIR working directory

        -p, --patch-directory DIR
                            directory with patches (default: "patches")

        -b, --backup always|onfail|never
                            create backup files for `quilt pop`
                            (default: onfail)

            --backup-count all|<n>
                            amount of backup files for `quilt pop` to create
                            (default: 100)

        -F, --fuzz <n>      maximal allowed fuzz (default: 0)

            --color always|auto|never
                            use colors in output (default: auto)

            --stats         print statistics in the end

        -h, --help          print this help menu


## Limitations compared to quilt & patch

* only patches in unified format
* file permissions in patch files are ignored
* date in patch files is ignored
* ... probably more that I don't know about

## Screenshot

Patch application failure:

![example-apply-failure](https://raw.githubusercontent.com/michalsrb/rapidquilt/master/doc/example-apply-failure.png "Example Apply Failure")
