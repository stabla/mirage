import rulesManagement as rm
import scenarioGen as sc

f = rm.parseFile('/Users/ahmed/mirage/mirage/tables/ble_tables.txt')

# print(f['BLE_TABLES'])
#print(f['GATT_MODIFIER'])

if('BLE_TABLES' in f ):
    d = rm.getConfigFile(f['BLE_TABLES'])
if('GATT_MODIFIER' in f ):
    att  =rm.getGattModifier(f['GATT_MODIFIER'])
print(d)
print(att)
# #a = d.groupCommandRules()
# sc.generateScenario(d)
