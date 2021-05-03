import sys
import rulesManagement as rm
import jinja2

def generateScenario(packetFilterRules):
    with open(sys.argv[1]) as templateFile:
        template = jinja2.Template(templateFile.read())
        template.stream(
            default=packetFilterRules.default,
            fileToParse=sys.argv[2],
            properRules=packetFilterRules.groupCommandRules()).dump(sys.argv[3])

# #Parse file
parsedFile = rm.parseFile(sys.argv[2])
# Extract BLE_TABLE RULES
if (rm.PACKET_FILTER_SECTION in parsedFile):
    ble_tables_rule = rm.getPacketFilterRulesForTemplate(parsedFile[rm.PACKET_FILTER_SECTION])
generateScenario(ble_tables_rule)
#print(ble_tables_rule.target)