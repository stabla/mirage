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

class TargetAddress(List):
    grammar = Target, blank, word,':',word,':',word,':',word,':',word,':',word

class TargetRules(List):
    grammar = TargetAddress, endl, AllRules

class ConfigFile(List):
    grammar = attr("Header", Header), endl, TargetRules

# Grammar definition for GATTFilter

class GATTHeader:
    grammar = K('GATT_FILTER')

class GATTFilterParameter(Keyword):
    grammar = Enum(K('entity'), K('type'), K('action'), K('serviceType'), K('uuid'), K('beginHandle'), K('endHandle'), K('declarationHandle'), K('valueHandle'), K('value'), K('permissions'),K('handle'))

class ValueOfGATTFilter(List):
    grammar = name(), word

class GATTKeyValue(Namespace):
    grammar = csl(ValueOfGATTFilter)
