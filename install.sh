#!/bin/bash

echo "[*] Starting Noctis installation..."
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "[*] Creating Python Virtual Environment..."
if ! python3 -m venv "$DIR/venv" >/dev/null 2>&1; then
    echo "[-] Error: python3-venv is not installed. Please install it using 'sudo apt install python3-venv' and try again."
    exit 1
fi

echo "[*] Installing required libraries..."
"$DIR/venv/bin/pip" install -r "$DIR/requirements.txt"
echo "[*] Configuring the global 'noctis' command..."
WRAPPER="/usr/local/bin/noctis"

sudo bash -c "cat > $WRAPPER" << EOL
#!/bin/bash
sudo "$DIR/venv/bin/python" "$DIR/Noctis.py" "\$@"
EOL
sudo chmod +x $WRAPPER
echo "[+] Installation Complete!"
echo "[+] You can now launch the tool from any terminal by typing: noctis"