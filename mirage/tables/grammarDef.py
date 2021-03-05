from pypeg2 import Enum, K, Keyword, List, Symbol, Namespace, csl, name, word, optional, endl, some, attr, blank,parse

class Header:
    grammar = K("BLE_TABLES")
class Target:
    grammar = K("TARGET")
class defautType:
    grammar = K("default")
    

class Parameter(Keyword):
    grammar = Enum(K("action"), K("type"), K("handle"), K("number"), K("value"))

class ValueOfParameter(List):
    grammar = name(), word

class ParameterAndValue(Namespace):
    grammar = csl(ValueOfParameter)

class Rule(List):
    grammar = ParameterAndValue, ParameterAndValue, ParameterAndValue, optional(
        ParameterAndValue), optional(ParameterAndValue), endl

class BlockRule(List):
    grammar = some(Rule)

class DefaultRule(str):
    grammar = attr("defautType", defautType), blank, word, optional(
        blank), endl


class AllRules(List):
    grammar = BlockRule, DefaultRule


class TargetRules(List):
    grammar = Target, blank, word, endl, AllRules

class ConfigFile(List):
    grammar = attr("Header", Header), endl, TargetRules