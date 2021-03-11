
import configparser
from mirage.tables.helpUtils import UUID, isHexadecimal, isPrintable


class Attribute:

    def __init__(self, ATThandle=None, ATTtype=None, ATTvalue=None):
        self.ATThandle = ATThandle
        self.ATTvalue = ATTvalue
        self.ATTtype = ATTtype

    def __str__(self):
        return '''
        ATThandle -> {0}
        ATTtype -> {1}
        ATTvalue -> {2}
        '''.format(self.ATThandle, self.ATTtype, self.ATTvalue)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.ATThandle == other.ATThandle and self.ATTvalue == other.ATTvalue and self.ATTtype == other.ATTtype
        return False


class Service():
    def __init__(self, beginHandle: int = -1, endHandle: int = -1, uuidValue: int = -1, serviceType: str = None):
        self.beginHandle = beginHandle
        self.endHandle = endHandle
        self.uuidValue = UUID(data=uuidValue)
        self.serviceType = serviceType

    def __str__(self):
        return '''
        Begin Handle -> {0}
        End Handle -> {1}
        UUID Value -> {2}
        ServiceType -> {3}
        '''.format(self.beginHandle, self.endHandle, self.uuidValue, self.serviceType)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.endHandle == other.endHandle and self.uuidValue == other.uuidValue and self.serviceType == other.serviceType
        return False


class Characteristic():
    def __init__(self, declarationHandle: int = -1, uuid: int = -1, valueHandle: int = -1, value: hex = -1, permissions: list = None):
        self.declarationHandle = declarationHandle
        self.uuid = UUID(data=uuid)
        self.valueHandle = valueHandle
        self.value = value
        self.permissions = permissions

    def __str__(self):
        return '''
        Declaration Handle -> {0}
        UUID -> {1}
        Value Handle -> {2}
        Value -> {3}
        Permissions -> {4}
        '''.format(self.declarationHandle, self.uuid, self.valueHandle, self.value, self.permissions)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.uuid == other.uuid and self.value == other.value and self.valueHandle == other.valueHandle
        return False


class Descriptor():
    def __init__(self, handle: int, uuid: int, value: hex):
        self.handle = handle
        self.uuid = UUID(data=uuid)
        self.value: UUID = value

    def __str__(self):
        return '''
        Handle -> {0}
        UUID -> {1}
        Value -> {2}
        '''.format(self.handle, self.uuid, self.value)

    def __eq__(self, other):
        if type(other) is type(self):
            return self.handle == other.handle and self.uuid == other.uuid and self.value == other.value
        return False
