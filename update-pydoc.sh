#!/usr/bin/env bash

set -euo pipefail

# This needs GNU seed with support for -z.

# Remove old temporary file if it exists
rm -f pydoc.md

for module in "chilldkg" "util"; do
pydoc-markdown -I python/chilldkg_ref -m "$module" "{renderer: {type: markdown, insert_header_anchors: false, render_module_header: no, format_code: no, header_level_by_type: {\"Function\": 4, \"Class\": 4, \"Method\": 5}, descriptive_class_title: \"$ Tuples\" }}" |
    # Remove header
    sed -z 's/[^#]*#/#/' |
    # Replace "Tuples" by "Exception" where appropriate
    sed -z 's/Error Tuples/Error Exception/g' |
    # Replace bold (**) by italics (*), but not for **must**, **must not**,
    # **should**, or **should not**.
    python3 -c "import re, sys; sys.stdout.write(re.sub(r'\*\*(?!must\*\*|should\*\*|must not\*\*|should not\*\*)(.*?)\*\*', r'*\1*', sys.stdin.read()))" >> pydoc.md

done

# Remove trailing newline
sed -z '$ s/\n$//' -i pydoc.md

# Hack to patch in the full definitions of our NamedTuples...
for name in SessionParams DKGOutput; do
    # Replace double \n\n by single \n because this is easier to work with
    sed -z 's/\n\n/\n/g' python/chilldkg_ref/chilldkg.py |
        # Match the definition (ended by a single empty line now)
        sed -n "/^class $name(NamedTuple):/,/^$/p" |
        # Remove docstring
        sed '/^ *"""/,/^ *"""/d' |
        # Remove method header lines (starting with four spaces and then "def" or "@")
        sed '/^    \(def\|@\)/d' |
        # Remove method body lines (lines indented with 8 or more spaces)
        sed '/^ \{8,\}/d' |
        # Remove code comment lines
        sed '/^    #/d' |
        # Remove trailing newline
        sed -z '$ s/\n$//' |
        # Do the patching
        sed -e "/^class $name(NamedTuple)/{r /dev/stdin" -e 'd;}' -i pydoc.md
done

# Remove trailing space
sed 's/[ \t]*$//' -i pydoc.md

# Clean README.md
sed -z -i README.md -e 's/<!--pydoc.md-->.*<!--end of pydoc.md-->/<!--pydoc.md-->\n<!--end of pydoc.md-->/'
# Insert pydoc.md into README
sed -i README.md -e '/<!--pydoc.md-->/r pydoc.md'
# Remove temporary file
rm pydoc.md

echo "Updated pydoc successfully"
