import jinja2
import rulesManagement as rm

with open('template.py.j2') as templateFile:
    template = jinja2.Template(templateFile.read())

def generateScenario(BleTable : rm.BleTable):
    template.stream(BleTable=BleTable, properRules=BleTable.groupCommandRules()).dump("mitm_test.py")
# Conversion Paquets Recus / Handler

