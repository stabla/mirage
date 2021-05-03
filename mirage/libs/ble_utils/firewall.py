import datetime
from mirage.libs.ble_utils.packets import BLEReadByTypeResponse
from mirage.libs.ble_utils.packets import BLEReadByGroupTypeResponse
from mirage.libs.ble_utils.dissectors import CharacteristicDeclaration,Service

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
        if (eventName not in self.eventCounter):
            self.eventCounter[eventName] = {}
            self.resetCounters(eventName)

    def countEvent(self, eventName: str):
        self.eventCounter[eventName][COUNTER_FIELD] += 1
        self.eventCounter[eventName][TIMESTAMP_FIELD] = datetime.datetime.now()

    def durationSinceLastPacket(self, eventName: str):
        delta = datetime.datetime.now() - self.getLastPacketTimestamp(
            eventName)
        return delta.seconds

    def getCurrentCount(self, eventName: str):
        return self.eventCounter[eventName][COUNTER_FIELD]

    def getLastPacketTimestamp(self, eventName: str):
        return self.eventCounter[eventName][TIMESTAMP_FIELD]

    def printEvent(self, eventName: str):
        print(eventName)
        print(self.getCurrentCount(eventName))
        print(self.durationSinceLastPacket(eventName))


class GATTEventManager:

    characteristicPackets = []
    # Filtering Characteristics
    def defineCharacteristic(self, information):
        characteristicDeclaration = CharacteristicDeclaration(data=information['value'][::-1])
        characteristic = {
            "declarationHandle": information["attributeHandle"],
            "valueHandle": characteristicDeclaration.valueHandle,
            "uuid": characteristicDeclaration.UUID,
            "permissionsFlag": characteristicDeclaration.permissionsFlag,
            "value": b""
        }
        return characteristic

    def findService(self, information):
        return Service(information['value'][::-1])

    def findCorrespodingUUID(self, packet):
        return list(map(self.defineCharacteristic, packet))

    def findCorrespodingService(self, packet):
        return list(map(self.indService, packet))

    def returnAttributesFromRawData(self, rawData):
        return BLEReadByTypeResponse(data=bytes.fromhex(rawData)).attributes

    def identityMap(self, handleMapperTab, decodedAttribute):
        handleMapperTab[
            decodedAttribute['declarationHandle']] = decodedAttribute

    def determineCharacteristics(self):
        handleMapperTab = {}
        for i in range(len(self.characteristicPackets)):
            handleAttributesNotDecoded = self.returnAttributesFromRawData(self.characteristicPackets[i])
            handleAttributesDecoded = self.findCorrespodingUUID(
                handleAttributesNotDecoded)
            [
                self.identityMap(handleMapperTab, attribute)
                for attribute in handleAttributesDecoded
            ]
        return handleMapperTab

    def remove_key(self, d, del_key):
        new_dict = {}
        for key, val in d.items():
            if key < del_key:
                new_dict[key] = val
            elif key > del_key:
                new_dict[key - 2] = val
            else:
                continue
        return new_dict

    def determineWhatFilter(self, blackList):
        flattenList = self.determineCharacteristics()
        keysToRemove = []
        for key, value in flattenList.items():
            print('{0} -> {1}'.format(key, str(value)))
            if 'uuid' in value and 'UUID16' in value['uuid'].content:
                uuid = str(hex(value['uuid'].content['UUID16']))
                if uuid in blackList:
                    keysToRemove.append(key)
                    keysToRemove.sort()
        return (flattenList, keysToRemove)

    def filter(self, flattenList, keysToRemove):
        dico = {}
        for i in range(len(keysToRemove)):
            dico = self.remove_key(flattenList, keysToRemove[i])
        return dico