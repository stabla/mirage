import rulesManagement as rm
import jinja2
import rulesManagement as rm

with open('/home/pi/mirage/mirage/tables/scenario/template.py.j2') as templateFile:
    template = jinja2.Template(templateFile.read())

def generateScenario(BleTable : rm.BleTable):
    template.stream(BleTable=BleTable, fileToParse='/home/pi/mirage/mirage/tables/scenario/ble_tables.txt' , properRules=BleTable.groupCommandRules()).dump("/home/pi/mirage/mirage/scenarios/mitm_test.py")

#Parse file
parsedFile = rm.parseFile('/home/pi/mirage/mirage/tables/scenario/ble_tables.txt')
#Extract BLE_TABLE RULES
if(rm.BLE_TABLES_SECTION in parsedFile):
    ble_tables_rule = rm.getBleTable(parsedFile[rm.BLE_TABLES_SECTION])
generateScenario(ble_tables_rule)