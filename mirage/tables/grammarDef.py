from pypeg2 import Enum, K, Keyword, List, Symbol, Namespace, csl, name, word, optional, endl, some, attr, blank, parse, maybe_some

# Grammar definition used  in common

class Header:
    grammar = K('BLE_TABLES')
class Target:
    grammar = K("TARGET")
class defautType:
    grammar = K("default")

class Entity:
    grammar = 'entity'

class EntityType:
    grammar = 'type'

class ActionType:
    grammar = 'action'

class ValueOfParameter(List):
    grammar = name(), blank, word, blank

class ParameterAndValue(Namespace):
    grammar = csl(ValueOfParameter)

# Grammar definition for BleTable

class BleTableRule(List):
    mandatory = ParameterAndValue, ParameterAndValue, ParameterAndValue
    grammar = mandatory, optional(ParameterAndValue), optional(ParameterAndValue),optional(endl), optional(ParameterAndValue(), endl


class BleTableBlockRule(List):
    grammar = some(BleTableRule)


class BleTableDefaultRule(str):
    grammar = attr("defautType", defautType), blank, word, optional(
        blank), endl


class BleTableAllRules(List):
    grammar = BleTableBlockRule, BleTableDefaultRule


class TargetAddress(List):
    grammar = Target, blank, word, ':', word, ':', word, ':', word, ':', word, ':', word


class TargetRules(List):
    grammar = TargetAddress, endl, BleTableAllRules


class BleTableSection(List):
    grammar = attr("Header", Header), endl, TargetRules, endl, 'END ', attr("Header", Header)

# Grammar definition for GATTFilter

class ruleStart(List):
    blank_word = blank, word, blank
    entity = Entity, blank_word
    entityType = EntityType, blank_word
    grammar = entity, entityType

class GATTFilterRule(List):
    grammar = ruleStart,optional(ParameterAndValue), optional(ParameterAndValue),optional(ParameterAndValue), endl

class GattFilterSection(List):
    grammar = some(GATTFilterRule)

# Grammar definition for GATTModifier

class ReplaceStatement(List):
    grammar = name(), blank, word, blank, word

class GATTModifyRule(List):
    start = 'ATT replace', blank
    grammar = start, ReplaceStatement, optional(endl), optional(ReplaceStatement), optional(endl), optional(ReplaceStatement), optional(endl)

class gattModifierSection(List):
    grammar = some(GATTModifyRule)