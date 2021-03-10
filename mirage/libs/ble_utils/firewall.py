import datetime
import configparser
import mirage.tables.rulesManagement as rm
from mirage.tables.bleATTManager import Attribute, Descriptor, Characteristic,Service

COUNTER_FIELD = 'counter'
TIMESTAMP_FIELD = 'timeStamp'
WINDOW_SIZE_IN_SECONDS = 20

class FirewallEventManager:

    def __init__(self, eventCounter: dict = {}):
        self.eventCounter = eventCounter

    def resetCounters(self, eventName: str):
        self.eventCounter[eventName][COUNTER_FIELD] = 0
        self.eventCounter[eventName][TIMESTAMP_FIELD] = datetime.datetime.now()

    def initCounters(self, eventName: str):
        if(eventName not in self.eventCounter):
            self.eventCounter[eventName] = {}
            self.resetCounters(eventName)

    def countEvent(self, eventName: str):
        self.eventCounter[eventName][COUNTER_FIELD] += 1
        self.eventCounter[eventName][TIMESTAMP_FIELD] = datetime.datetime.now()

    def durationSinceLastPacket(self, eventName: str):
        delta = datetime.datetime.now()-self.getLastPacketTimestamp(eventName)
        return delta.seconds

    def getCurrentCount(self, eventName: str):
        return self.eventCounter[eventName][COUNTER_FIELD]

    def getLastPacketTimestamp(self, eventName: str):
        return self.eventCounter[eventName][TIMESTAMP_FIELD]

    def printEvent(self, eventName: str):
        print(eventName)
        print(self.getCurrentCount(eventName))
        print(self.durationSinceLastPacket(eventName))


class Firewall_GattServer:

    def importATT(self, filename="ATT_SLAVE_MITM", forbiddenAtrributes=[], replaceList=[],server=None):
        print("Importing ATT layer datas from "+filename+" ...")
        config = configparser.ConfigParser()
        config.read(filename)
        attribute = Attribute()
        for handle in config.sections():
            attHandle = int(handle, 16)
            infos = config[handle]
            attType = infos.get("type")
            attValue = bytes.fromhex(
                infos.get("value") if infos.get("value") is not None else "")
            attribute = Attribute(attHandle, attType, attValue)
            forbidden = self.__authorizeGattInfo(attribute, forbiddenAtrributes)
            if forbidden:
                print(attribute)
                print('was refused')
                # result = self.__getReplacement(attribute,replaceList)
                # if result != False:
                #     server.addAttribute(handle=attribute.ATThandle,value=attribute.ATTvalue,type=attribute.ATTvalue,permissions=["Read","Write"])
            else:
                server.addAttribute(handle=attHandle,value=attValue,type=attType,permissions=["Read","Write"])
                pass


    def importGATT(self, filename="GATT_SLAVE_MITM", forbiddenServices=[], forbiddenCharacteristics=[], forbiddenDescriptors=[],server=None):
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
                    service = Service(beginHandle=startHandle,
                                      endHandle=endHandle, uuidValue=uuid, serviceType=infos.get('servicetype'))
                    forbidden = self.__authorizeGattInfo(service, forbiddenServices)
                    if not forbidden:
                        if infos.get("servicetype") == "primary":
                            server.addPrimaryService(uuid,startHandle)
                        else:
                            server.addSecondaryService(uuid,startHandle)
                    else:
                        print(service)
                        print('was refused')  
                elif infos.get("type") == "characteristic":
                    declarationHandle = int(element, 16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    valueHandle = int(infos.get("valuehandle"), 16)
                    value = bytes.fromhex(infos.get("value"))
                    permissions = infos.get("permissions").split(",")
                    characteristic = Characteristic(declarationHandle=declarationHandle,
                                                    uuid=uuid, valueHandle=valueHandle, value=value, permissions=permissions)
                    forbidden = self.__authorizeGattInfo(
                        characteristic, forbiddenCharacteristics)
                    if not forbidden:
                        server.addCharacteristic(uuid,value,declarationHandle,valueHandle,permissions)
                    else :
                        print(characteristic)
                        print('was refused')
                elif infos.get("type") == "descriptor":
                    handle = int(element, 16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    value = bytes.fromhex(infos.get("value"))
                    descriptor = Descriptor(
                        handle=handle, uuid=uuid, value=value)
                    forbidden = self.__authorizeGattInfo(
                        descriptor, forbiddenDescriptors)
                    if not forbidden:
                        server.addDescriptor(uuid,value,handle)
                    else:
                        print(descriptor)
                        print('was refused') 

    def __authorizeGattInfo(self, gattInformation, gattForbiddenRules):
        return gattInformation in gattForbiddenRules

    def __getReplacement(self, attribute, replaceList):
        for substitutionTuple in replaceList:
            if substitutionTuple[0] == attribute:
                return substitutionTuple[1]
        return False
    
    def doFiltering(self,characteristicRules,serviceRules,descriptorRules,attributeRules,gatt_modifier_rules):
        self.importATT("/Users/ahmed/mirage/ATT_SLAVE_MITM",attributeRules,gatt_modifier_rules)
        self.importGATT('/Users/ahmed/mirage/GATT_SLAVE_MITM',serviceRules,characteristicRules, descriptorRules)


def checkRules(pathOfBleTables):
    # Parse file
    parsedFile = rm.parseFile(pathOfBleTables)
    # Extract GATTFILTER RULES
    if(rm.GATT_FILTER_SECTION in parsedFile):
        gatt_filter_rules = rm.getGattFilterRules(
            parsedFile[rm.GATT_FILTER_SECTION])
    # Extract ATT SUBSTITUTION RULES
    if(rm.GATT_MODIFIER_SECTION in parsedFile):
        gatt_modifier_rules = rm.getGattModifierRules(
            parsedFile[rm.GATT_MODIFIER_SECTION])
    # Filter Rules By Type
    characteristicRules = rm.getCharacteristicRules(gatt_filter_rules)
    serviceRules = rm.getServiceRules(gatt_filter_rules)
    descriptorRules = rm.getDescriptorRules(gatt_filter_rules)
    attributeRules = rm.getAttributeRules(gatt_filter_rules)
    return (characteristicRules,serviceRules,descriptorRules,attributeRules,gatt_modifier_rules)
