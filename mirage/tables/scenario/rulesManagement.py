from collections import namedtuple
from utils import *

GATT_FILTER_SECTION = 'GATT_FILTER'
BLE_TABLES_SECTION = 'BLE_TABLES'
GATT_MODIFIER_SECTION = 'GATT_MODIFIER'
SECTIONS = {
    GATT_FILTER_SECTION: r'GATT_FILTER(.*?)END', BLE_TABLES_SECTION: r'BLE_TABLES(.*?)END'}


class BleTable:
    def __init__(self, target: str = '', default: str = '', rules: list = []):
        self.target = target
        self.default = True if default == 'allow' else False
        self.rules = rules

    def __str__(self):
        return '''
Target -> {0}
Default -> {1}
list -> 
{2}
        '''.format(self.target, self.default, self.printList())

    def groupCommandRules(self):
        return groupByRuleType(self.rules)

    def printList(self):
        return '\n'.join([str(item) for item in self.rules])


def parseFile(pathOfFile: str):
    parsedText = {}
    # Open File
    with open(pathOfFile, 'r') as file:
        fileConfiguration = file.read()
    # Apply Regex to delimitate file parts
    sectionsAndText = {section: applyRegexToText(
        fileConfiguration, associatedRegex) for section, associatedRegex in SECTIONS.items()}
    # For each separated part on file
    for section in sectionsAndText:
        if sectionsAndText[section] != None:
            if section in (GATT_FILTER_SECTION, BLE_TABLES_SECTION):
                # Apply it's grammar to get consistent informations
                parsedText[section] = parsePacketAndGATTRules(
                    sectionsAndText[section])
            else:
                raise Exception('Error During Parsing')
    return parsedText

# With parsed text extract rule to put it on object instancied with introspection


def getBleTableRule(parsedRule, className):
    return namedtuple(className, parsedRule.keys())(*parsedRule.values())
    
# Get a BleTable object by extracting target, rules and default action
def getBleTable(bleTable):
    target = bleTable[0]['TARGET']
    default = bleTable[len(bleTable)-1]['default']
    attributesTocheck = bleTable[1:len(bleTable)-1]
    rules = [getBleTableRule(attribute, 'BLETableRule')
             for attribute in attributesTocheck]
    return BleTable(target, default, rules)


def getGattFilterTable(gattFilterSection):
    return [getBleTableRule(attribute, 'GATTFilterRule') for attribute in gattFilterSection]
