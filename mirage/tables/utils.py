import re
import csv

GATT_FILTER_SECTION = 'GATT_FILTER'
BLE_TABLES_SECTION = 'BLE_TABLES'
GATT_MODIFIER_SECTION = 'GATT_MODIFIER'
SECTIONS = {GATT_FILTER_SECTION: r'GATT_FILTER(.*?)END', BLE_TABLES_SECTION: r'BLE_TABLES(.*?)END',
            GATT_MODIFIER_SECTION: r'GATT_MODIFIER(.*?)END'}


def applyRegexToText(text: str, regex: str):
    result = re.search(regex, text, re.DOTALL)
    if result:
        return result.group(1)
    else:
        return None


def groupByRuleType(rulesList: list):
    dictionnary= {}
    for rule in rulesList:
        if rule.typeCommand not in dictionnary:
            dictionnary[rule.typeCommand]= []
        dictionnary[rule.typeCommand].append(rule)
    mapHandlersToCommand(dictionnary)
    return dictionnary


def mapHandlersToCommand(rulesGroupedByTypes: dict):
    reader= csv.DictReader(open("/Users/ahmed/mirage/mirage/tables/commandsToHandlers.csv", 'r'))
    for line in reader:
        rulesGroupedByTypes[line['handler']]= rulesGroupedByTypes.pop(line['command'])
