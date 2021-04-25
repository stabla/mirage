import re
import csv
from pyparsing import Word, printables, LineEnd, Optional, OneOrMore

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
    dictionnary = {}
    for rule in rulesList:
        if hasattr(rule, 'type') and rule.type not in dictionnary:
            dictionnary[rule.type] = []
        dictionnary[rule.type].append(rule)
    for packetType in dictionnary :
        dictionnary[packetTypeToRule(packetType)[1]]= dictionnary.pop(packetType)
    return dictionnary


def list2Dict(valuesList):
    dictionary = {}
    for i in range(0, len(valuesList)-1, 2):
        dictionary[valuesList[i]] = valuesList[i+1]
    return dictionary


def parsePacketAndGATTRules(rules):
    grammar = OneOrMore(Word(printables) +
                        Word(printables)+Optional(LineEnd()))
    result = list(grammar.parseString(rules))
    smallerLists = [l.split(',') for l in ','.join(result).split('\n')]
    ruleValueDictList = []
    if [''] in smallerLists:
        smallerLists.remove([''])
    for rule in smallerLists:
        rule.remove('')
        ruleValueDictList.append(list2Dict(rule))
    return ruleValueDictList

def packetTypeToRule(packet):
    switcher = {
        'BLEWriteCommand': ('BLEHandleValueRule', 'onMasterWriteCommand'),
        'BLEHandleValueNotification': ('BLEHandleValueRule', 'onSlaveHandleValueNotification'),
        'BLEPairingRequest': ('BLEPairingRule', 'onMasterPairingRequest'),
        'BLEPairingResponse': ('BLEPairingRule', 'onSlavePairingResponse')
    }
    return switcher.get(packet, None)
