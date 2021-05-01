import struct
import rulesManagement as rm
import jinja2
with open('/home/pi/mirage/mirage/tables/scenario/template.py.j2'
          ) as templateFile:
    template = jinja2.Template(templateFile.read())


def generateScenario(BleTable):
    template.stream(
        BleTable=BleTable,
        fileToParse='/home/pi/mirage/mirage/tables/scenario/ble_tables.txt',
        properRules=BleTable.groupCommandRules()).dump(
            "/home/pi/mirage/mirage/scenarios/mitm_test.py")


# #Parse file
parsedFile = rm.parseFile(
    '/home/pi/mirage/mirage/tables/scenario/ble_tables.txt')
# Extract BLE_TABLE RULES
if (rm.BLE_TABLES_SECTION in parsedFile):
    ble_tables_rule = rm.getBleTable(parsedFile[rm.BLE_TABLES_SECTION])
if (rm.GATT_FILTER_SECTION in parsedFile):
    gattFilterRules = rm.getGattFilterTable(parsedFile[rm.GATT_FILTER_SECTION])

#generateScenario(ble_tables_rule)
