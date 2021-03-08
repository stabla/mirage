from pypeg2 import Enum, K, Keyword, List, Symbol, Namespace, csl, name, word, optional, endl, some, attr, blank, parse, maybe_some

class Header:
    grammar = K('BLE_TABLES')
class Target:
    grammar = K("TARGET")
class defautType:
    grammar = K("default")
class GATTFilterHeader:
    grammar = K('GATT_FILTER')

class GATTModifierHeader:
    grammar = K('GATT_MODIFIER')

class Entity:
    grammar = 'entity'

class EntityType:
    grammar = 'type'

class ActionType:
    grammar = 'action'

class Parameter(Keyword):
    grammar = Enum(K("action"), K("type"), K(
        "handle"), K("number"), K("value"))


class ValueOfParameter(List):
    grammar = name(), blank, word, blank


class ParameterAndValue(Namespace):
    grammar = csl(ValueOfParameter)


class Rule(List):
    mandatory = ParameterAndValue, ParameterAndValue, ParameterAndValue
    grammar = mandatory, optional(ParameterAndValue), optional(ParameterAndValue), endl


class BlockRule(List):
    grammar = some(Rule)


class DefaultRule(str):
    grammar = attr("defautType", defautType), blank, word, optional(
        blank), endl


class AllRules(List):
    grammar = BlockRule, DefaultRule


class TargetAddress(List):
    grammar = Target, blank, word, ':', word, ':', word, ':', word, ':', word, ':', word


class TargetRules(List):
    grammar = TargetAddress, endl, AllRules


class ConfigFile(List):
    grammar = attr("Header", Header), endl, TargetRules, endl, 'END ', attr("Header", Header)

# Grammar definition for GATTFilter
class ruleStart(List):
    blank_word = blank, word, blank
    entity = Entity, blank_word
    entityType = EntityType, blank_word
    grammar = entity, entityType

class GATTRule(List):
    grammar = ruleStart,optional(ParameterAndValue), optional(ParameterAndValue),optional(ParameterAndValue), endl

class GATTFilterRulesBlock(List):
    grammar = some(GATTRule)

class BAV(List):
    grammar = name(), blank, word, blank, word

class GATTModifyRule(List):
    attR = 'ATT replace', blank
    grammar = attR, BAV, optional(endl), optional(BAV), optional(endl), optional(BAV), optional(endl)

class GATTModifierRulesBlock(List):
    grammar = some(GATTModifyRule)

class GATTPartOfFile(List):
    grammar = attr("GATTFilterHeader",GATTFilterHeader), endl, GATTFilterRulesBlock, 'END ', attr("GATTFilterHeader", GATTFilterHeader)

class GATTModifierPart(List):
    grammar = attr("GATT_MODIFIER",GATTModifierHeader), endl, GATTModifierRulesBlock,endl, 'END ', attr("GATT_MODIFIER", GATTModifierHeader)
