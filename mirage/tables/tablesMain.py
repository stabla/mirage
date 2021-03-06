import rulesManagement as rm
import scenarioGen as sc

f = rm.parseFile('/Users/ahmed/mirage/mirage/tables/ble_tables.txt')
d = rm.getConfigFile(f)
a = d.groupCommandRules()
sc.generateScenario(d)
