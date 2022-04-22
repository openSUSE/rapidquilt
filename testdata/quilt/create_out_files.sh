#! /bin/sh

for t in {ok,fail}/* ; do
    rm -r "$t"/expect
    cp -r "$t"/input "$t"/expect
    pushd "$t"/expect
    quilt push -a
    find . -type f -name .\* -print0 | xargs -0 rm
    popd
done
