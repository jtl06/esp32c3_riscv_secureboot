#!/bin/bash
set -e

# Check if IDF_PATH is set, otherwise try to source it
if [ -z "$IDF_PATH" ]; then
    if [ -f "$HOME/esp/esp-idf/export.sh" ]; then
        echo "Sourcing ESP-IDF from $HOME/esp/esp-idf/export.sh"
        # Prepend Python 3.13 environment to avoid Python 3.14 detection
        export PATH="$HOME/.espressif/python_env/idf5.3_py3.13_env/bin:$PATH"
        . "$HOME/esp/esp-idf/export.sh"
    else
        echo "Error: IDF_PATH is not set and could not find export.sh in default location."
        exit 1
    fi
fi

echo "Starting Serial Monitor..."
echo "Press Ctrl+] to exit."

# Run monitor on the bootloader project
idf.py -C bootloader monitor
