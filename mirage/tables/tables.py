# from the documentation
'''
int f(int a, long b)
{
    do_this;
    do_that;
}'''

from pypeg2 import *

testGrammar = "TARGET FC58FA040413 \n action deny number 1 type BLEWriteCommand handle 0x29 value 0x2 action deny number 1 type BLEWriteCommand handle 0x29 value 0x0  action deny number 3 type BLEHandleValueNotification handle 0x25 value 0x1 default allow"
testcommonInstruction = """
BLE_TABLES
TARGET FC58FA040413
action deny number 1 type BLEWriteCommand handle 0x29 value 0x2
action deny number 1 type BLEWriteCommand handle 0x29 value 0x0
action deny number 3 type BLEHandleValueNotification handle 0x25 value 0x1
default allow
"""
class Header(Keyword):
    grammar = Enum((K("BLE_TABLES")))

class CommonType(Keyword):
    grammar=Enum(K("action"), K("type"), K(
        "handle"), K("number"), K("value"))


class Target(Keyword):
    grammar=Enum(K("TARGET"))


class defautType:
    grammar=K("default")


class commonInstruction(str):
    grammar=attr("commonType", CommonType), blank, word, optional(endl)


class InstructionList(List):
    grammar=some(commonInstruction)


class defautInstruction(str):
    grammar=attr("defautType", defautType), blank, word, optional(
        blank), endl


class TargetInstructions(List):
    grammar=Target, blank, word, endl, InstructionList, defautInstruction


class FileParser(List):
    grammar=attr("Header", Header), endl, maybe_some(TargetInstructions)

with open('ble_tables.txt', 'r') as file:
    fileConfiguration = file.read()

f=parse(fileConfiguration, FileParser)
print(f)


# f = parse(testGrammar,FileParser)
