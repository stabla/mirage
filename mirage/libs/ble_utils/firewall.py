import datetime
from mirage.libs.ble_utils import *

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

class GATTEventManager():
    def defineCharacteristic(information):
        characteristicDeclaration = CharacteristicDeclaration(
            data=information['value'][::-1])
        characteristic = {
            "declarationHandle": information["attributeHandle"],
            "valueHandle": characteristicDeclaration.valueHandle,
            "uuid": characteristicDeclaration.UUID,
            "permissionsFlag": characteristicDeclaration.permissionsFlag,
            "value": b""
        }
        return characteristic


    def findService(information):
        return Service(information['value'][::-1])


    def findCorrespodingUUID(packet):
        return list(map(defineCharacteristic, packet))


    def findCorrespodingService(packet):
        return list(map(findService, packet))


    def returnAttributesFromRawData(rawData):
        return BLEReadByTypeResponse(data=bytes.fromhex(rawData)).attributes


    def identityMap(handleMapperTab, decodedAttribute):
        handleMapperTab[decodedAttribute['declarationHandle']] = decodedAttribute


    def determineCharacteristics():
        handleMapperTab = {}
        for i in range(0, len(handleValues)-1, 1):
            handleAttributesNotDecoded = returnAttributesFromRawData(handleValues[i])
            handleAttributesDecoded = findCorrespodingUUID(handleAttributesNotDecoded)
            [identityMap(handleMapperTab, attribute)for attribute in handleAttributesDecoded]
        return handleMapperTab


    def remove_key(d, del_key):
        new_dict = {}
        for key, val in d.items():
            if key < del_key:
                new_dict[key] = val
            elif key > del_key:
                new_dict[key-2] = val
            else:
                continue
        return new_dict


    blackList = ['0x2a24', '0x2a23']
    flattenList = determineCharacteristics()
    keysToRemove = []
    for key, value in flattenList.items():
        print('{0} -> {1}'.format(key, str(value)))
        if 'uuid' in value and 'UUID16' in value['uuid'].content :
            uuid = str(hex(value['uuid'].content['UUID16']))
            print(uuid)
            if uuid in blackList:
                keysToRemove.append(key)
                keysToRemove.sort()
        print('\n')
