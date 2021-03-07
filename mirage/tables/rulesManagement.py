import grammarDef as bleTableGrammar
from typing import List
import csv
import re


class AbstractRule:
    def __init__(self,action: str = ''):
        self.action = action
class BLETableRule(AbstractRule):

    def __init__(self, number: int = 1, action: str = '', typeCommand: str = '', handle: hex = 0x0, value: hex = 0x0):
        self.number = number
        self.typeCommand = typeCommand
        self.handle = handle
        self.value = value
        super()

    def __str__(self):
        # return "Number of paquets to block  -> " + str(self.number) + " \nAction to do -> " + self.action + "\nCommandBleToFilter ->" + self.typeCommand + "\nHandle To Manage ->" + self.handle + "\nHandle To Value ->" + self.value
        return str(self.number) + " " + str(self.action) + " " + self.typeCommand + self.handle + self.value


class FileConfig:
    def __init__(self, target: str = '', default: str = '', rules: list = []):
        self.target = target
        self.default = True if default == 'allow' else False
        self.rules = rules

    def __str__(self):
        return "Target  -> " + str(self.target) + " \nDefault Action to do -> " + str(self.default) + "\n" + self.printList()

    def groupCommandRules(self):
        return groupByRuleType(self.rules)

    def printList(self):
        return ', '.join([str(item) for item in self.rules])


GATT_FILTER_SECTION = 'GATT_FILTER'
BLE_TABLES_SECTION = 'BLE_TABLES'
GATT_MODIFIER_SECTION = 'GATT_MODIFIER'
SECTIONS = {GATT_FILTER_SECTION: r'GATT_FILTER(.*?)END', BLE_TABLES_SECTION: r'BLE_TABLES(.*?)END',
            GATT_MODIFIER_SECTION: r'GATT_MODIFIER(.*?)END'}


def parseFile(pathOfFile: str):
    parsedText = {}
    with open(pathOfFile, 'r') as file:
        fileConfiguration = file.read()
    my_dictionary = {section: applyRegexToText(
        fileConfiguration, associatedRegex) for section, associatedRegex in SECTIONS.items()}
    for section in my_dictionary:
        if my_dictionary[section] != None:
            if section == GATT_FILTER_SECTION:
                parsedText[section] = bleTableGrammar.parse(
                    my_dictionary[section], bleTableGrammar.GATTFilterRulesBlock)
            elif section == BLE_TABLES_SECTION:
                parsedText[section] = bleTableGrammar.parse(
                    my_dictionary[section], bleTableGrammar.TargetRules)
            elif section == GATT_MODIFIER_SECTION:
                parsedText[section] = bleTableGrammar.parse(
                    my_dictionary[section], bleTableGrammar.GATTModifierRulesBlock)
            else:
                raise Exception('Error During Parsing')
    return parsedText


def applyRegexToText(text: str, regex: str):
    result = re.search(regex, text, re.DOTALL)
    if result:
        return result.group(1)
    else:
        return None


def mapRule(correctInstruction: bleTableGrammar.ParameterAndValue) -> BLETableRule:
    InstructionItems = {}
    for element in correctInstruction:
        for key, value in element.items():
            InstructionItems[str(key)] = value[0]
    return BLETableRule(number=int(InstructionItems['number']), action=InstructionItems['action'], typeCommand=InstructionItems['type'],
                     handle=InstructionItems['handle'], value=InstructionItems['value'])


def getConfigFile(parsedAttributes: bleTableGrammar.ConfigFile):
    target = ':'.join(parsedAttributes[0][0][1:])
    default = parsedAttributes[0][1][1]
    attributesTocheck = parsedAttributes[0][1][0]
    rules = list(map(mapRule, attributesTocheck))
    return FileConfig(target, default, rules)


def groupByRuleType(rulesList: List[BLETableRule]):
    dictionnary = {}
    for rule in rulesList:
        if rule.typeCommand not in dictionnary:
            dictionnary[rule.typeCommand] = []
        dictionnary[rule.typeCommand].append(rule)
    mapHandlersToCommand(dictionnary)
    return dictionnary


def mapHandlersToCommand(rulesGroupedByTypes: dict) -> dict:
    reader = csv.DictReader(
        open("/Users/ahmed/mirage/mirage/tables/commandsToHandlers.csv", 'r'))
    for line in reader:
        rulesGroupedByTypes[line['handler']
                            ] = rulesGroupedByTypes.pop(line['command'])
