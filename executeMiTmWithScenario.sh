sudo cp mirage/scenarios/mitm_test.py /root/.mirage/scenarios/
sudo ./mirage_launcher ble_mitm TARGET=$1 SCENARIO='mitm_test' 