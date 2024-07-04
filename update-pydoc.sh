#!/bin/sh

# This needs GNU seed with support for -z.

pydoc-markdown -I python/chilldkg_ref -m chilldkg |
    # Remove trailing newline
    sed -z '$ s/\n$//' |
    # Remove header
    sed -z 's/.*#### hostpubkey/#### hostpubkey/' |
    # Remove <a> elements
    sed -z 's|<a id="[^"]*"></a>\n\n||g' |
    # Replace bold (**) by italics (*)
    sed -z 's/\*\*/*/g' > pydoc.md &&
    # Clean README.md
    sed -z -i README.md -e 's/<!--pydoc.md-->.*<!--end of pydoc.md-->/<!--pydoc.md-->\n<!--end of pydoc.md-->/' &&
    # Insert pydoc.md into README
    sed -i README.md -e '/<!--pydoc.md-->/r pydoc.md' &&
    # Remove temporary file
    rm pydoc.md
