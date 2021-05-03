mirageFolder='/home/pi/mirage/'
nameOfFileToWrite='mitm_test'
tablesFolder=$mirageFolder'mirage/tables/'
scenariosFolder=$mirageFolder'mirage/scenarios/'
templateFile=$tablesFolder'template.py.j2'
fileToParse=$tablesFolder'ble_tables.txt'
fileToWrite=$scenariosFolder$nameOfFileToWrite'.py'
target=`python3 mirage/tables/generateScenario.py $templateFile $fileToParse $fileToWrite`
echo "$target"
sudo cp $fileToWrite /root/.mirage/scenarios/
sudo ./mirage_launcher ble_mitm TARGET=$target SCENARIO=$nameOfFileToWrite --debug
