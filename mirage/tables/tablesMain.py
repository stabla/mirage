import unittest
import rulesManagement as rm

f = rm.parseFile('ble_tables.txt')
d = rm.getConfigFile(f)
a = d.groupCommandRules()
for key,value in a.items():
    print(key,value)