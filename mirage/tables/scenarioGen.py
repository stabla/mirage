import jinja2
import mirage.tables.rulesManagement as rm

with open('mirage/tables/template.py.j2') as templateFile:
    template = jinja2.Template(templateFile.read())

def generateScenario(BleTable : rm.BleTable):
    template.stream(BleTable=BleTable, properRules=BleTable.groupCommandRules()).dump("mirage/tables/mitm_test.py")
# Conversion Paquets Recus / Handler

