# If on linux:
sudo mkdir -pv /var/log/sawtooth
sudo chown -R ${USER} /var/log/sawtooth
sudo apt install libsecp256k1-dev -y
pip3 install sawtooth_sdk cbor

python3 main.py -v

