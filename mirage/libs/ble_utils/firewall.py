import datetime
import configparser

COUNTER_FIELD = 'counter'
TIMESTAMP_FIELD = 'timeStamp'
WINDOW_SIZE_IN_SECONDS = 20

class ATT_Attribute:
	def __init__(self,handle=None,value=None,type=None, permissions=None):
		self.handle = handle
		self.value = value

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


class Service:
    def __init__(self, beginHandle: int, endHandle: int, uuidValue: int, serviceType: str):
        self.beginHandle = beginHandle
        self.endHandle = endHandle
        self.uuidValue = uuidValue
        self.serviceType = serviceType

    def __str__(self):
        return '''
        Begin Handle -> {0}
        End Handle -> {1}
        UUID Value -> {2}
        ServiceType -> {3}
        '''.format(hex(self.beginHandle), hex(self.endHandle), self.uuidValue, self.serviceType)


class Firewall_GattServer:
    # Import ATT Config file
    def nop(self):
        return None

    def importATT(self, filename="ATT_SLAVE_MITM"):
        print("Importing ATT layer datas from "+filename+" ...")
        attributes = ["1"]
        config = configparser.ConfigParser()
        config.read(filename)
        for handle in config.sections():
            attHandle = int(handle, 16)
            infos = config[handle]
            attType = infos.get("type")
            attValue = bytes.fromhex(infos.get("value") if infos.get("value") is not None else "")
            wholeAttribute = ATT_Attribute(attHandle,attValue)
            attributes.append(wholeAttribute)
            # Filter should go there
            # check_firewall_rules()
            #   - has firewall a rule for ATT type?
            # if (0 == 1):
            #     # put your logic there
            #     ...
            # #   - has firewall a rule for ATT service?
            # if (0 == 1):
            #     # put your logic there
            #     ...
            # #   - has firewall a rule for banning system id?
            # if (0 == 1):
            #     # put your logic there
            #     ...
        return attributes

    """
    "Je peux vous proposer une approche intéressante:
    l'idée serait de manipuler les requêtes de découverte des services pour exposer
    au Master un serveur GATT différent de celui proposé par l'objet.
    Par exemple, pouvoir supprimer séléctivement certaines characteristics sensibles,
    certains services qui leakent des infos sur l'objet, etc. Evidemment,
    le MiTM devrait faire la "correspondance" entre le serveur GATT "réel" et celui exposé au Central.
    """
# cette fonction d

    def importGATT(self, filename="GATT_SLAVE_MITM"):
        print("Importing GATT layer datas from "+filename+" ...")
        primaryServices = []
        config = configparser.ConfigParser()
        config.read(filename)
        for element in config.sections():
            infos = config[element]
            if "type" in infos:
                if infos.get("type") == "service":
                    startHandle = int(element, 16)
                    endHandle = int(infos.get("endhandle"), 16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    primaryServices.append(Service(beginHandle=startHandle, endHandle=endHandle, uuidValue=infos.get(
                        "uuid"), serviceType=infos.get('servicetype')))
                    if infos.get("servicetype") == "primary":
                        # self.server.addPrimaryService(uuid,startHandle)
                        self.nop()
                    else:
                        # self.server.addSecondaryService(uuid,startHandle)
                        self.nop()
                # elif infos.get("type") == "characteristic":
                #     declarationHandle = int(element, 16)
                #     uuid = bytes.fromhex(infos.get("uuid"))
                #     valueHandle = int(infos.get("valuehandle"), 16)
                #     value = bytes.fromhex(infos.get("value"))
                #     permissions = infos.get("permissions").split(",")
                #     # self.server.addCharacteristic(uuid,value,declarationHandle,valueHandle,permissions)
                # elif infos.get("type") == "descriptor":
                #     handle = int(element, 16)
                #     uuid = bytes.fromhex(infos.get("uuid"))
                #     value = bytes.fromhex(infos.get("value"))
                    # self.server.addDescriptor(uuid, value, handle)
        return primaryServices

    def doLogic(self, variable):
        print(variable)
        print("\n")
