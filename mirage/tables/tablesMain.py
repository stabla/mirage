import rulesManagement as rm
import scenarioGen as sc
from bleATTManager import Firewall_GattServer

#Parse file
parsedFile = rm.parseFile('/Users/ahmed/mirage/mirage/tables/ble_tables.txt')
#Extract BLE_TABLE RULES
if(rm.BLE_TABLES_SECTION in parsedFile):
    ble_tables_rule = rm.getBleTable(parsedFile[rm.BLE_TABLES_SECTION])
#Extract ATT SUBSTITUTION RULES
if(rm.GATT_FILTER_SECTION in parsedFile):
    gatt_filter_rules = rm.getGattFilterRules(parsedFile[rm.GATT_FILTER_SECTION])
#Extract ATT SUBSTITUTION RULES
if(rm.GATT_MODIFIER_SECTION in parsedFile):
    gatt_modifier_rule = rm.getGattModifierRules(parsedFile[rm.GATT_MODIFIER_SECTION])

#Filter Rules By Type
characteristicRules = rm.getCharacteristicRules(gatt_filter_rules)
serviceRules = rm.getServiceRules(gatt_filter_rules)
descriptorRules = rm.getDescriptorRules(gatt_filter_rules)
attributeRules = rm.getAttributeRules(gatt_filter_rules)
sc.generateScenario(ble_tables_rule)

# Filtering Effectively ATT/GATT Objects
firewall = Firewall_GattServer()
firewall.doFiltering(characteristicRules,serviceRules,descriptorRules,attributeRules,gatt_modifier_rule)