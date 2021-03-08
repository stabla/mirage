import grammarDef as bleTableGrammar
from typing import List
from bleATTManager import Attribute,Descriptor,Characteristic,Service
from utils import *

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
        '''.format(self.number,self.action,self.typeCommand,self.handle,self.value)

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
        '''.format(self.target,self.default,self.printList())

    def groupCommandRules(self):
        return groupByRuleType(self.rules)

    def printList(self):
        return ' , '.join([str(item) for item in self.rules])

def parseFile(pathOfFile: str):
    parsedText = {}
    with open(pathOfFile, 'r') as file:
        fileConfiguration = file.read()
    sectionsAndText = {section: applyRegexToText(fileConfiguration, associatedRegex) for section, associatedRegex in SECTIONS.items()}
    for section in sectionsAndText:
        if sectionsAndText[section] != None:
            if section == GATT_FILTER_SECTION:
                parsedText[section] = bleTableGrammar.parse(sectionsAndText[section], bleTableGrammar.GATTFilterRulesBlock)
            elif section == BLE_TABLES_SECTION:
                parsedText[section] = bleTableGrammar.parse(sectionsAndText[section], bleTableGrammar.TargetRules)
            elif section == GATT_MODIFIER_SECTION:
                parsedText[section] = bleTableGrammar.parse(sectionsAndText[section], bleTableGrammar.GATTModifierRulesBlock)
            else:
                raise Exception('Error During Parsing')
    return parsedText

def mapRule(parsedRule: bleTableGrammar.ParameterAndValue):
    ruleParameters = {}
    for parameter in parsedRule:
        for key, value in parameter.items():
            ruleParameters[str(key)] = value[0]
    return BLETableRule(number=int(ruleParameters['number']), action=ruleParameters['action'], typeCommand=ruleParameters['type'],
                        handle=ruleParameters['handle'], value=ruleParameters['value'])


def getBleTable(parsedAttributes: bleTableGrammar.ConfigFile):
    target = ':'.join(parsedAttributes[0][1:])
    default = parsedAttributes[1][1]
    attributesTocheck = parsedAttributes[1][0]
    rules = list(map(mapRule, attributesTocheck))
    return BleTable(target, default, rules)


def getGattModifierRule(rule: bleTableGrammar.ParameterAndValue):
    before = after = Attribute('', None, None)
    for case in rule:
        if case.name == 'handle':
            before.ATThandle, after.ATThandle = case[0], case[1]
        if case.name == 'value':
            before.ATTvalue, after.ATThandle = case[0], case[1]
        if case.name == 'type':
            before.ATTtype, after.ATTtype = case[0], case[1]
    return before, after


def getGattModifierRules(gattModifierRules):
    return list(map(getGattModifierRule, gattModifierRules))


def getRuleFilterRule(rule):
    ruleParameters = {}
    for parameter in rule[1:]:
        for key, value in parameter.items():
            ruleParameters[str(key)] = value[0]
    gattType = rule[0][3]
    if(gattType == 'Service'):
        return Service(serviceType=ruleParameters['serviceType'],endHandle=ruleParameters['endHandle'],uuidValue=bytes.fromhex(ruleParameters['uuid']))
    elif(gattType == 'Characteristic'):
        return Characteristic(uuid=bytes.fromhex(ruleParameters['uuid']),value=ruleParameters['value'],valueHandle=ruleParameters['valueHandle'])
    elif(gattType == 'Descriptor'):
        return Descriptor(uuid=bytes.fromhex(ruleParameters['uuid']),value=ruleParameters['value'],handle=ruleParameters['handle'])
    elif(gattType == 'Attribute'):
        return Attribute(ATThandle=ruleParameters['handle'],ATTtype=ruleParameters['type'],ATTvalue=ruleParameters['value'])
    else:
        return None

def getGattFilterRules(gattParserRules):
    return list(map(getRuleFilterRule, gattParserRules))

