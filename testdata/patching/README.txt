These files are processed by the "tests::testdata_patching::all_files" test.

That test will open every "*.patch" file, parse it and then load the target
file and apply the patch to it. The patches in this directory should contain
exactly one FilePatch. The result is then compared with file matching "*.out"
file.

The ".out" files can be generated using the "create_out_files.sh" script, which
calls the regular patch command.

Both the test and the "create_out_files.sh" script recognize special headers in
the patch:
  * fuzz: n
