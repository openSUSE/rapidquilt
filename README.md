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

            --dry-run       do not save any changes

            --stats         print statistics in the end

            --mmap          mmap files instead of reading into buffers. This may
                            reduce memory usage and improve performance in some
                            cases. Warning: You must ensure that no external
                            program will modify the files while rapidquilt is
                            running, otherwise you may get incorrect results or
                            even crash.

        -h, --help          print this help menu


## Limitations compared to quilt & patch

* only patches in unified format
* date in patch files is ignored
* ... probably more that I don't know about

## Screenshot

Patch application failure:

![example-apply-failure](https://raw.githubusercontent.com/michalsrb/rapidquilt/master/doc/example-apply-failure.png "Example Apply Failure")
