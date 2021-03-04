import grammarDef as bleTableGrammar
from typing import List


class RuleClass:

    def __init__(self, number: int = 0, action: str = '', typeCommand: str = '', handle: hex = 0x0, value: hex = 0x0):
        self.number = number
        self.action = action
        self.typeCommand = typeCommand
        self.handle = handle
        self.value = value

    def __str__(self):
        # return "Number of paquets to block  -> " + str(self.number) + " \nAction to do -> " + self.action + "\nCommandBleToFilter ->" + self.typeCommand + "\nHandle To Manage ->" + self.handle + "\nHandle To Value ->" + self.value
        return str(self.number) + " " + self.action + " " + self.typeCommand + self.handle + self.value


class FileConfig:

    def __init__(self, target: str = '', defaut: str = '', rules: list = []):
        self.target = target
        self.defaut = defaut
        self.rules = rules

    def __str__(self):
        return "Target  -> " + str(self.target) + " \nDefault Action to do -> " + self.defaut + "\n" + self.printList()

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
    target = parsedAttributes[0][1]
    default = parsedAttributes[0][2][1]
    attributesTocheck = parsedAttributes[0][2][0]
    rules = list(map(mapRule, attributesTocheck))
    return FileConfig(target, default, rules)


def groupByRuleType(rulesList: List[RuleClass]):
    dictionnary = {}
    for rule in rulesList:
        if rule.typeCommand not in dictionnary:
            dictionnary[rule.typeCommand] = []
        dictionnary[rule.typeCommand].append(rule)
        # dictionnary[rule.typeCommand].append(str(rule))
    return dictionnary
