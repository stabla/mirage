from collections import namedtuple
from utils import *


class packetFilterRules:
    def __init__(self, target: str = '', default: str = '', rules: list = []):
        self.target = target
        self.default = True if default == ALLOW_STRING else False
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
            if section == PACKET_FILTER_SECTION:
                # Apply it's grammar to get consistent informations
                parsedText[section] = parsePacketFilterRules(
                    sectionsAndText[section])
    return parsedText

# With parsed text extract rule to put it on object instancied with introspection


def getPacketFilterRule(parsedRule, className):
    return namedtuple(className, parsedRule.keys())(*parsedRule.values())

# Get a packetFilterRules object by extracting target, rules and default action


def getPacketFilterRulesForTemplate(parsedRules):
    target = parsedRules[0][TARGET_STRING]
    default = parsedRules[len(parsedRules)-1][DEFAULT_STRING]
    attributesTocheck = parsedRules[1:len(parsedRules)-1]
    rules = [getPacketFilterRule(attribute, PACKET_FILTER_CLASS_STRING)
             for attribute in attributesTocheck]
    return packetFilterRules(target, default, rules)
