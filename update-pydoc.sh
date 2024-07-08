#!/usr/bin/env bash

set -euo pipefail

# This needs GNU seed with support for -z.

pydoc-markdown -I python/chilldkg_ref -m chilldkg '{renderer: {type: markdown, insert_header_anchors: false, render_module_header: no, format_code: no, header_level_by_type: {"Function": 4, "Class": 4, "Method": 5}, descriptive_class_title: "$ Tuples" }}' |
    # Remove trailing newline
    sed -z '$ s/\n$//' |
    # Remove header
    sed -z 's/[^#]*#/#/' |
    # Replace bold (**) by italics (*)
    sed -z 's/\*\*/*/g' > pydoc.md

# Hack to patch in the full definitions of our NamedTuples...

for name in SessionParams DKGOutput; do
    # Replace double \n\n by single \n because this is easier to work with
    sed -z 's/\n\n/\n/g' python/chilldkg_ref/chilldkg.py |
        # Match the definition (ended by a single empty line now)
        sed -n "/^class $name(NamedTuple):/,/^$/p" |
        # Remove docstring
        sed '/^ *"""/,/^ *"""/d' |
        # Remove trailing newline
        sed -z '$ s/\n$//' |
        # Do the patching
        sed -e "/^class $name/{r /dev/stdin" -e 'd;}' -i pydoc.md
done

# Remove trailing space
sed 's/[ \t]*$//' -i pydoc.md

# Clean README.md
sed -z -i README.md -e 's/<!--pydoc.md-->.*<!--end of pydoc.md-->/<!--pydoc.md-->\n<!--end of pydoc.md-->/'
# Insert pydoc.md into README
sed -i README.md -e '/<!--pydoc.md-->/r pydoc.md'
# Remove temporary file
rm pydoc.md
