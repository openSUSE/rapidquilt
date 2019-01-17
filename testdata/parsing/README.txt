These files are processed by the "tests::testdata_parsing::all_files" test.

The test will open every file ending with "*.patch", parse it and then write it
out in a "canonical" form. It compares it with the expected form from the
"*.patch-expected" file. If there is difference, it saves its version to
"*.patch-bad" file.

If the patch fails to parse, then test will try to open "*.error" file and
checks if the content of the file is contained in the error message
(either user-friendly printed and debug printed).

This can be used to verify that the parser understands all important data
in the patch.
