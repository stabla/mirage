import re
import csv
from pyparsing import Word, printables, LineEnd, Optional, OneOrMore, ZeroOrMore, Literal

GATT_FILTER_SECTION = 'GATT_FILTER'
PACKET_FILTER_SECTION = 'BLE_TABLES'
GATT_MODIFIER_SECTION = 'GATT_MODIFIER'
SECTIONS = {GATT_FILTER_SECTION: r'GATT_FILTER(.*?)END', PACKET_FILTER_SECTION: r'BLE_TABLES(.*?)END',
            GATT_MODIFIER_SECTION: r'GATT_MODIFIER(.*?)END'}
TARGET_STRING = 'TARGET'
DEFAULT_STRING = 'default'
PACKET_FILTER_CLASS_STRING = 'PacketFilterRule'
ACTION_STRING = 'action'
TYPE_STRING = 'type'
ALLOW_STRING = 'allow'
DENY_STRING = 'deny'

# Function which use regex to separate multiple parts of text
# (useful if needed to apply different grammar for each part)


def applyRegexToText(text: str, regex: str):
    result = re.search(regex, text, re.DOTALL)
    if result:
        return result.group(1)
    else:
        return None

# Grouping all rules found on packet filter part in order to write
# all the conditions for each rule inside the same handler in scenario


def groupByRuleType(rulesList: list):
    dictionnaryGroupingRules = {}
    handlerDictionnary = {}
    for rule in rulesList:
        if hasattr(rule, TYPE_STRING) and rule.type not in dictionnaryGroupingRules:
            dictionnaryGroupingRules[rule.type] = []
        dictionnaryGroupingRules[rule.type].append(rule)
    for packetType in dictionnaryGroupingRules:
        handlerDictionnary[packetTypeToRule(
            packetType)] = dictionnaryGroupingRules[packetType]
    return handlerDictionnary

# Useful to convert a list to a dictionnary after parsing


def __list2Dict(valuesList):
    dictionary = {}
    for i in range(0, len(valuesList)-1, 2):
        dictionary[valuesList[i]] = valuesList[i+1]
    return dictionary

# Parsing rule for packet filter part of rules files


def parsePacketFilterRules(rules):
    header = Literal(TARGET_STRING) + Word(printables) + LineEnd()
    grammar = header + Literal(ACTION_STRING) + Word(printables) + Literal(TYPE_STRING) + Word(printables) + \
        Optional(LineEnd()) + ZeroOrMore((Word(printables) +
                                          Word(printables)+Optional(LineEnd())))
    result = list(grammar.parseString(rules))
    smallerLists = [l.split(',') for l in ','.join(result).split('\n')]
    ruleList = []
    if [''] in smallerLists:
        smallerLists.remove([''])
    for rule in smallerLists:
        rule.remove('')
        ruleList.append(__list2Dict(rule))
    return ruleList

# Get the corresponding Handler depending on packet Type


def packetTypeToRule(packet):
    switcher = {
        'BLEWriteCommand':  'onMasterWriteCommand',
        'BLEHandleValueNotification': 'onSlaveHandleValueNotification',
        'BLEPairingRequest':  'onMasterPairingRequest',
        'BLEPairingResponse': 'onSlavePairingResponse',
        'BLEWriteRequest': 'onMasterWriteRequest'
    }
    return switcher.get(packet, None)
