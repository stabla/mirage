import rulesManagement as rm
import scenarioGen as sc

f = rm.parseFile('/Users/ahmed/mirage/mirage/tables/ble_tables.txt')

if(rm.BLE_TABLES_SECTION in f):
    ble_tables_rule = rm.getBleTable(f[rm.BLE_TABLES_SECTION])
if(rm.GATT_MODIFIER_SECTION in f):
    gatt_modifier_rule = rm.getGattModifierRules(f[rm.GATT_MODIFIER_SECTION])
if(rm.GATT_FILTER_SECTION in f):
    gatt_filter_rules = rm.getGattFilterRules(f[rm.GATT_FILTER_SECTION])

print(ble_tables_rule)
# print(gatt_modifier_rule)
# for element in gatt_filter_rules:
#     print(element)

sc.generateScenario(ble_tables_rule)
