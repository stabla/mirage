import grammarDef as bleTableGrammar
from typing import List
import csv

class RuleClass:

    def __init__(self, number: int = 1, action: str = '', typeCommand: str = '', handle: hex = 0x0, value: hex = 0x0):
        self.number = number
        self.action = True if action == 'allow' else False
        self.typeCommand = typeCommand
        self.handle = handle
        self.value = value

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


def parseFile(pathOfFile: str) -> bleTableGrammar.ConfigFile:
    with open(pathOfFile, 'r') as file:
        fileConfiguration = file.read()
    return bleTableGrammar.parse(fileConfiguration, bleTableGrammar.ConfigFile)


def mapRule(correctInstruction: bleTableGrammar.ParameterAndValue) -> RuleClass:
    InstructionItems = {}
    for element in correctInstruction:
        for key, value in element.items():
            InstructionItems[str(key)] = value[0]
    return RuleClass(number=int(InstructionItems['number']), action=InstructionItems['action'], typeCommand=InstructionItems['type'],
                     handle=InstructionItems['handle'], value=InstructionItems['value'])


def getConfigFile(parsedAttributes: bleTableGrammar.ConfigFile) -> FileConfig:
    target = ':'.join(parsedAttributes[0][0][1:])
    default = parsedAttributes[0][1][1]
    attributesTocheck = parsedAttributes[0][1][0]
    rules = list(map(mapRule, attributesTocheck))
    return FileConfig(target, default, rules)


def groupByRuleType(rulesList: List[RuleClass]):
    dictionnary = {}
    for rule in rulesList:
        if rule.typeCommand not in dictionnary:
            dictionnary[rule.typeCommand] = []
        dictionnary[rule.typeCommand].append(rule)
    mapHandlersToCommand(dictionnary)
    return dictionnary

def mapHandlersToCommand(rulesGroupedByTypes : dict) -> dict:
    reader = csv.DictReader(open("/Users/ahmed/mirage/mirage/tables/commandsToHandlers.csv",'r'))
    for line in reader:
        rulesGroupedByTypes[line['handler']] = rulesGroupedByTypes.pop(line['command'])
