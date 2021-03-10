import grammarDef as bleTableGrammar
from utils import *

GATT_FILTER_SECTION = 'GATT_FILTER'
BLE_TABLES_SECTION = 'BLE_TABLES'
GATT_MODIFIER_SECTION = 'GATT_MODIFIER'
SECTIONS = {GATT_FILTER_SECTION: r'GATT_FILTER(.*?)END', BLE_TABLES_SECTION: r'BLE_TABLES(.*?)END',
            GATT_MODIFIER_SECTION: r'GATT_MODIFIER(.*?)END'}


class BLETableRule():
    def __init__(self, number: int = 1, action: str = '', typeCommand: str = '', handle: hex = 0x0, value: hex = 0x0):
        self.number = number
        self.typeCommand = typeCommand
        self.handle = handle
        self.value = value
        self.action = True if action == 'allow' else False

    def __str__(self):
        return '''
        Number of paquet to block -> {0}
        Action -> {1}
        TypeCommand -> {2}
        Handle -> {3}
        Value -> {4}
        '''.format(self.number, self.action, self.typeCommand, self.handle, self.value)


class BleTable:
    def __init__(self, target: str = '', default: str = '', rules: list = []):
        self.target = target
        self.default = True if default == 'allow' else False
        self.rules = rules

    def __str__(self):
        return '''
        Target -> {0}
        Default -> {1}
        list -> {2}
        '''.format(self.target, self.default, self.printList())

    def groupCommandRules(self):
        return groupByRuleType(self.rules)

    def printList(self):
        return ' , '.join([str(item) for item in self.rules])


def parseFile(pathOfFile: str):
    parsedText = {}
    #Open File
    with open(pathOfFile, 'r') as file:
        fileConfiguration = file.read()
    #Apply Regex to delimitate file parts
    sectionsAndText = {section: applyRegexToText(
        fileConfiguration, associatedRegex) for section, associatedRegex in SECTIONS.items()}
    # For each separated part on file
    for section in sectionsAndText:
        if sectionsAndText[section] != None:
            if section == GATT_FILTER_SECTION:
                #Apply it's grammar to get consistent informations
                parsedText[section] = bleTableGrammar.parse(
                    sectionsAndText[section], bleTableGrammar.GattFilterSection)
            elif section == BLE_TABLES_SECTION:
                #Apply it's grammar to get consistent information
                parsedText[section] = bleTableGrammar.parse(
                    sectionsAndText[section], bleTableGrammar.TargetRules)
            elif section == GATT_MODIFIER_SECTION:
                #Apply it's grammar to get consistent information
                parsedText[section] = bleTableGrammar.parse(
                    sectionsAndText[section], bleTableGrammar.gattModifierSection)
            else:
                raise Exception('Error During Parsing')
    return parsedText

#With parsed text extract rule to put it on object
def getBleTableRule(parsedRule: bleTableGrammar.ParameterAndValue):
    ruleParameters = {}
    for parameter in parsedRule:
        for key, value in parameter.items():
            ruleParameters[str(key)] = value[0]
    return BLETableRule(number=int(ruleParameters['number']), action=ruleParameters['action'], typeCommand=ruleParameters['type'],
                        handle=ruleParameters['handle'], value=ruleParameters['value'])

#Get a BleTable object by extracting target, rules and default action 
def getBleTable(bleTable: bleTableGrammar.BleTableSection):
    target = ':'.join(bleTable[0][1:])
    default = bleTable[1][1]
    attributesTocheck = bleTable[1][0]
    rules = list(map(getBleTableRule, attributesTocheck))
    return BleTable(target, default, rules)
