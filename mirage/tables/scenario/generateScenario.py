import struct
from importer import *
# with open('/Users/ahmed/mirage/mirage/tables/scenario/template.py.j2') as templateFile:
#     template = jinja2.Template(templateFile.read())

# def generateScenario(BleTable):
#     template.stream(BleTable=BleTable, fileToParse='/Users/ahmed/mirage/mirage/tables/scenario/ble_tables.txt',
#                     properRules=BleTable.groupCommandRules()).dump("/Users/ahmed/mirage/mirage/scenarios/mitm_test.py")

# # #Parse file
# parsedFile = rm.parseFile('/Users/ahmed/mirage/mirage/tables/scenario/ble_tables.txt')
# # Extract BLE_TABLE RULES
# if(rm.BLE_TABLES_SECTION in parsedFile):
#     ble_tables_rule = rm.getBleTable(parsedFile[rm.BLE_TABLES_SECTION])
# if (rm.GATT_FILTER_SECTION in parsedFile):
#     gattFilterRules = rm.getGattFilterTable(parsedFile[rm.GATT_FILTER_SECTION])
# print(gattFilterRules)
# print(ble_tables_rule.groupCommandRules()['onMasterPairingRequest'][0])
# generateScenario(ble_tables_rule)


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
    handleValues = ['070800020900292a0a00020b00242a0c00020d00252a', '070e00020f00272a1000021100262a1200021300282a', '071400021500232a16000217002a2a1800021900502a',
                    '151b001c1c0000000000000000b000405104c1ff00f0', '151f001c200000000000000000b000405104c2ff00f0', '072400102500e1ff', '072800042900062a']
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

print(keysToRemove)

for i in range(0, len(keysToRemove)):
    flattenList = remove_key(flattenList, keysToRemove[i])

for key, value in flattenList.items():
    print('{0} -> {1}'.format(key, str(value)))
    print('\n')
