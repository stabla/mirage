import jinja2
import rulesManagement as rm

with open('/Users/ahmed/mirage/mirage/tables/template.py.j2') as templateFile:
    template = jinja2.Template(templateFile.read())

def generateScenario(fileConfig : rm.FileConfig):
    template.stream(fileConfig=fileConfig, properRules=fileConfig.groupCommandRules()).dump("/Users/ahmed/mirage/mirage/tables/firewall.py")
# Conversion Paquets Recus / Handler

