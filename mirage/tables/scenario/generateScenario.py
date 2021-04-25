import rulesManagement as rm
import jinja2

with open('/Users/ahmed/mirage/mirage/tables/scenario/template.py.j2') as templateFile:
    template = jinja2.Template(templateFile.read())

def generateScenario(BleTable):
    template.stream(BleTable=BleTable, fileToParse='/Users/ahmed/mirage/mirage/tables/scenario/ble_tables.txt',
                    properRules=BleTable.groupCommandRules()).dump("/Users/ahmed/mirage/mirage/scenarios/mitm_test.py")

# #Parse file
parsedFile = rm.parseFile('/Users/ahmed/mirage/mirage/tables/scenario/ble_tables.txt')
# Extract BLE_TABLE RULES
if(rm.BLE_TABLES_SECTION in parsedFile):
    ble_tables_rule = rm.getBleTable(parsedFile[rm.BLE_TABLES_SECTION])
#print(ble_tables_rule.groupCommandRules()['onMasterPairingRequest'][0])
generateScenario(ble_tables_rule)