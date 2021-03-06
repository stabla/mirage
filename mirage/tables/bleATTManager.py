
import configparser
from helpUtils import UUID, isHexadecimal, isPrintable

class Attribute:
    def __init__(self, ATThandle, ATTtype, ATTvalue):
        self.ATThandle = ATThandle
        self.ATTvalue = ATTvalue
        if isinstance(ATTtype, int):
            self.ATTtype = UUID(UUID16=ATTtype)
        elif isinstance(ATTtype, bytes):
            self.ATTtype = UUID(data=ATTtype)
        elif isHexadecimal(ATTtype) and len(ATTtype) <= 6:
            self.ATTtype = UUID(UUID16=int(ATTtype, 16))
        elif isHexadecimal(ATTtype) and len(ATTtype) > 6:
            self.ATTtype = UUID(UUID128=bytes.fromhex(ATTtype))
        else:
            self.ATTtype = UUID(name=ATTtype)

    def __str__(self):
        return '''
        ATThandle -> {0}
        ATTtype -> {1}
        ATTvalue -> {2}
        '''.format(self.ATThandle, self.ATTtype, self.ATTvalue)

    def setType(self, type):
        print(type)


class Service:
    def __init__(self, beginHandle: int, endHandle: int, uuidValue: int, serviceType: str):
        self.beginHandle = beginHandle
        self.endHandle = endHandle
        self.uuidValue : UUID = UUID(data=uuidValue)
        self.serviceType = serviceType

    def __str__(self):
        return '''
        Begin Handle -> {0}
        End Handle -> {1}
        UUID Value -> {2}
        ServiceType -> {3}
        '''.format(hex(self.beginHandle), hex(self.endHandle), self.uuidValue, self.serviceType)


class Firewall_GattServer:
      
    allowedGATTServices = []
    allowedATT_Attributes = []

    def importATT(self, filename="ATT_SLAVE_MITM"):
        print("Importing ATT layer datas from "+filename+" ...")
        attributes = []
        config = configparser.ConfigParser()
        config.read(filename)
        for handle in config.sections():
            attHandle = int(handle, 16)
            infos = config[handle]
            attType = infos.get("type")
            attValue = bytes.fromhex(infos.get("value") if infos.get("value") is not None else "")
            attribute = Attribute(attHandle, attType, attValue)
            attributes.append(attribute)
            if(attribute.ATTtype.name != 'Characteristic Declaration'):
                self.allowedATT_Attributes.append(attribute)
            granted = self.attFilter(attribute,self.allowedATT_Attributes)
            print( " Cet attribut a été {0} ".format( 'autorisé' if granted else 'refusé'))

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
                  service = Service(beginHandle=startHandle, endHandle=endHandle, uuidValue=uuid, serviceType=infos.get('servicetype'))
                  primaryServices.append(service)
                  #Va autorisé un service qui a un vrai nom (temporaire, le temps de faire la config par fichier Generic Access,Generic Attribute,Device Information, Immediate Alert)
                  if(service.uuidValue.name != None):
                    self.allowedGATTServices.append(service)
                  granted = self.gattFilter(service,self.allowedGATTServices)
                  print( " Ce service a été {0} ".format( 'autorisé' if granted else 'refusé'))

    def doLogic(self, variable):
        print(variable)
        print("\n")

    def gattFilter(self, service:Service, filterList: list):
          return service in firewall.allowedGATTServices
    
    def attFilter(self, attribute:Attribute, filterList: list):
          return attribute in firewall.allowedATT_Attributes

firewall = Firewall_GattServer()
firewall.importGATT('/Users/ahmed/mirage/ATT_SLAVE_MITM')

# for service in firewall.allowedGATTServices:
#       print(service)

firewall.importATT("/Users/ahmed/mirage/ATT_SLAVE_MITM")
# for attribute in attributes:
#     print(attribute)
