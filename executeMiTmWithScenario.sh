python3 mirage/tables/scenario/generateScenario.py
file=$1
sudo cp mirage/scenarios/$file.py /root/.mirage/scenarios/
sudo ./mirage_launcher ble_mitm TARGET=$2 SCENARIO=$file CONNECTION_TYPE=random --debug