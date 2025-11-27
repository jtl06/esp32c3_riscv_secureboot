#!/bin/bash
set -e

# Check if IDF_PATH is set, otherwise try to source it
if [ -z "$IDF_PATH" ]; then
    if [ -f "$HOME/esp/esp-idf/export.sh" ]; then
        echo "Sourcing ESP-IDF from $HOME/esp/esp-idf/export.sh"
        . "$HOME/esp/esp-idf/export.sh"
    else
        echo "Error: IDF_PATH is not set and could not find export.sh in default location."
        exit 1
    fi
fi

# 1. Setup Python Environment
if [ ! -d "tools/venv" ]; then
    echo "Creating python virtual environment..."
    python3 -m venv tools/venv
    source tools/venv/bin/activate
    pip install -r tools/requirements.txt
else
    source tools/venv/bin/activate
fi

# 2. Generate Keys if not exist
if [ ! -f "tools/private.pem" ]; then
    echo "Generating keys..."
    python tools/manager.py generate-keys
    mv private.pem tools/private.pem
    mv public.pem tools/public.pem
fi

# 3. Bridge Key to C
echo "Bridging public key..."
cat tools/public.pem | sed 's/^/"/' | sed 's/$/\\n"/' > bootloader/main/public_key_include.h

# 4. Build User App
echo "Building User App..."
cd app
idf.py build
cd ..

# 5. Sign User App
echo "Signing User App..."
python tools/manager.py sign app/build/hello_world.bin --output signed_app.bin --private-key tools/private.pem

# 6. Build & Flash Bootloader
echo "Building and Flashing Bootloader..."
cd bootloader
idf.py build flash
cd ..

# 7. Flash Signed App
echo "Flashing Signed App..."
# Assuming default port, or use ESPPORT env var
esptool.py write_flash 0x20000 signed_app.bin

echo "Done! Monitor with: idf.py -C bootloader monitor"
