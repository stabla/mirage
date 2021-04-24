#python3 mirage/tables/scenario/generateScenario.py
file='smTest'
sudo cp mirage/scenarios/$file.py /root/.mirage/scenarios/
sudo ./mirage_launcher ble_mitm TARGET=$1 SCENARIO=$file