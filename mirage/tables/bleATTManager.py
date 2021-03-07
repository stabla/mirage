
import configparser
from helpUtils import UUID, isHexadecimal, isPrintable

class Attribute:
    def __init__(self, ATThandle, ATTtype, ATTvalue):
        self.ATThandle = ATThandle
        self.ATTvalue = ATTvalue
        self.ATTtype = ATTtype
        # if isinstance(ATTtype, int):
        #     self.ATTtype = UUID(UUID16=ATTtype)
        # elif isinstance(ATTtype, bytes):
        #     self.ATTtype = UUID(data=ATTtype)
        # elif isHexadecimal(ATTtype) and len(ATTtype) <= 6:
        #     self.ATTtype = UUID(UUID16=int(ATTtype, 16))
        # elif isHexadecimal(ATTtype) and len(ATTtype) > 6:
        #     self.ATTtype = UUID(UUID128=bytes.fromhex(ATTtype))
        # else:
        #     self.ATTtype = None #UUID(name=ATTtype) 

    def __str__(self):
        return '''
        ATThandle -> {0}
        ATTtype -> {1}
        ATTvalue -> {2}
        '''.format(self.ATThandle, self.ATTtype, self.ATTvalue)


class Service:
    def __init__(self, beginHandle: int, endHandle: int, uuidValue: int, serviceType: str):
        self.beginHandle = beginHandle
        self.endHandle = endHandle
        self.uuidValue: UUID = UUID(data=uuidValue)
        self.serviceType = serviceType

    def __str__(self):
        return '''
        Begin Handle -> {0}
        End Handle -> {1}
        UUID Value -> {2}
        ServiceType -> {3}
        '''.format(hex(self.beginHandle), hex(self.endHandle), self.uuidValue, self.serviceType)


class Characteristic:
    def __init__(self, declarationHandle: int, uuid: int, valueHandle: int, value: hex, permissions: list):
        self.declarationHandle = declarationHandle
        self.uuid = UUID(data=uuid)
        self.valueHandle = valueHandle
        self.value: value
        self.permissions = permissions

    def __str__(self):
        return '''
        Declaration Handle -> {0}
        UUID -> {1}
        Value Handle -> {2}
        Value -> {3}
        Permissions -> {4}
        '''.format(hex(self.declarationHandle), self.uuid, self.valueHandle, self.value, self.permissions)


class Descriptor:
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


class Firewall_GattServer:

    allowedGATTServices = []
    allowedGATTCharacteristics = []
    allowedGATTDescriptors = []
    allowedATT_Attributes = []

    def importATT(self, filename="ATT_SLAVE_MITM"):
        print("Importing ATT layer datas from "+filename+" ...")
        config = configparser.ConfigParser()
        config.read(filename)
        for handle in config.sections():
            attHandle = int(handle, 16)
            infos = config[handle]
            attType = infos.get("type")
            attValue = bytes.fromhex(
                infos.get("value") if infos.get("value") is not None else "")
            attribute = Attribute(attHandle, attType, attValue)
            if(attribute.ATTtype.name != 'Characteristic Declaration'):
                self.allowedATT_Attributes.append(attribute)
            granted = self.attFilter(attribute)
            print(" Cet attribut a été {0} ".format(
                'autorisé' if granted else 'refusé'))

    def importGATT(self, filename="GATT_SLAVE_MITM"):
        print("Importing GATT layer datas from "+filename+" ...")
        config = configparser.ConfigParser()
        config.read(filename)
        for element in config.sections():
            infos = config[element]
            if "type" in infos:
                if infos.get("type") == "service":
                    startHandle = int(element, 16)
                    endHandle = int(infos.get("endhandle"), 16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    service = Service(beginHandle=startHandle, endHandle=endHandle,uuidValue=uuid, serviceType=infos.get('servicetype'))
                    self.gattFilter(service)
                elif infos.get("type") == "characteristic":
                    declarationHandle = int(element, 16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    valueHandle = int(infos.get("valuehandle"), 16)
                    value = bytes.fromhex(infos.get("value"))
                    permissions = infos.get("permissions").split(",")
                    characteristic = Characteristic(
                        declarationHandle=declarationHandle, uuid=uuid, valueHandle=valueHandle, value=value, permissions=permissions)
                    self.gattFilter(characteristic)
                elif infos.get("type") == "descriptor":
                    handle = int(element, 16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    value = bytes.fromhex(infos.get("value"))
                    descriptor = Descriptor(
                        handle=handle, uuid=uuid, value=value)
                    self.gattFilter(descriptor)

    def doLogic(self, variable):
        print(variable)
        print("\n")

    def gattFilter(self, gattInformation):
        if isinstance(gattInformation, Service):
            return gattInformation in self.allowedGATTServices
        elif isinstance(gattInformation, Characteristic):
            return gattInformation in self.allowedGATTCharacteristics
        elif isinstance(gattInformation, Descriptor):
            return gattInformation in self.allowedGATTDescriptors

    def attFilter(self, attribute: Attribute):
        return attribute in self.allowedATT_Attributes


# firewall = Firewall_GattServer()
# firewall.importGATT('/Users/ahmed/mirage/GATT_SLAVE_MITM')
# firewall.importATT("/Users/ahmed/mirage/ATT_SLAVE_MITM")