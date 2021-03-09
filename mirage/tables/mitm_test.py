from mirage.core import scenario, interpreter, module
from mirage.libs import io, ble, bt, utils
from mirage.libs.ble_utils.firewall import *
import configparser,os.path,subprocess

class mitm_test(scenario.Scenario):

    def onStart(self):
        self.a2sEmitter = self.module.a2sEmitter
        self.a2sReceiver = self.module.a2sReceiver
        self.a2mEmitter = self.module.a2mEmitter
        self.a2mReceiver = self.module.a2mReceiver
        self.firewallManager = FirewallEventManager()
        self.dependencies = ["ble_discover"] # for GATT
        io.info("MITM started !")
        return True
    
    def onEnd(self):
        io.info("MITM finished")
        return True

    
    def onMasterWriteCommand(self,packet):
        #Defines what apprend exactly
        currentEvent = self.getEventName(packet.handle, packet.value, self.onMasterWriteCommand.__name__)
        #Init counter of the number of packets if it's the first time that packet is handled 
        self.firewallManager.initCounters(currentEvent)
        #Computes duration in seconds where last time where packet comes, 0 is default value
        sinceLastEventDuration = self.firewallManager.durationSinceLastPacket(currentEvent)
        if packet.handle == 0x29 and 0x2 in packet.value:
            #Increment counter of one packet and update timestamp of last packet that comes
            self.firewallManager.countEvent(currentEvent)
            # packet is allowed
            return True
        if packet.handle == 0x29 and 0x0 in packet.value:
            #Increment counter of one packet and update timestamp of last packet that comes
            self.firewallManager.countEvent(currentEvent)
            # packet is allowed
            return True
        else : #default case of the rule
            return self.__drop(currentEvent)

    def onSlaveHandleValueNotification(self,packet):
        #Defines what apprend exactly
        currentEvent = self.getEventName(packet.handle, packet.value, self.onSlaveHandleValueNotification.__name__)
        #Init counter of the number of packets if it's the first time that packet is handled 
        self.firewallManager.initCounters(currentEvent)
        #Computes duration in seconds where last time where packet comes, 0 is default value
        sinceLastEventDuration = self.firewallManager.durationSinceLastPacket(currentEvent)
        if packet.handle == 0x25 and 0x1 in packet.value:
            #Increment counter of one packet and update timestamp of last packet that comes
            self.firewallManager.countEvent(currentEvent)
            #Check if flow of packets is allowed or not
            if self.firewallManager.getCurrentCount(currentEvent) >= 2 and sinceLastEventDuration < WINDOW_SIZE_IN_SECONDS:
                return self.__drop(currentEvent)
            elif sinceLastEventDuration > WINDOW_SIZE_IN_SECONDS: # After a certain time counters go down
                self.firewallManager.resetCounters(currentEvent)
            else: # number of packet flows is inferior of limit during window
                return True
        else : #default case of the rule
            return self.__drop(currentEvent)

    # Drop packets and reset counter of packets after drops
    def __drop(self, name: str):
        io.info("According to our firewall policy we choose to drop the packet")
        self.firewallManager.resetCounters(name)
        return False

    def getEventName(self, handle: hex, value: hex, handlerName: str):
        return "{0}_{1}_{2} ".format(str(handle),str(value),handlerName)

    """
    GATT CENTRAL
    """
    def onMasterReadByGroupTypeRequest(self, packet):
        io.info("Read By Group Type Request (from Master): startHandle = "+hex(packet.startHandle)+
                " / endHandle = "+hex(packet.endHandle)+" / uuid = "+hex(packet.uuid))
        io.info("Response from MITM ReadGroup ...")
        (success,response) = self.server.readByGroupType(packet.startHandle, packet.endHandle, packet.uuid)
        if success:
            io.displayPacket(ble.BLEReadByGroupTypeResponse(attributes=response))
            self.a2mEmitter.sendp(ble.BLEReadByGroupTypeResponse(attributes=response))
        else:
            self.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x10,ecode=response,handle=packet.startHandle))
        return False

    def onMasterReadByTypeRequest(self, packet):
        io.info("Read By Type Request : startHandle = "+hex(packet.startHandle)+
            " / endHandle = "+hex(packet.endHandle)+" / uuid = "+hex(packet.uuid))
        io.info("Response from MITM ReadType ...")
        (success,response) = self.server.readByType(packet.startHandle,packet.endHandle,packet.uuid)
        if (response == []):
            io.warning(" MITM: Empty Response ! Try again ... ")
            self.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x08,ecode=0, handle=packet.startHandle))
        else:
            if success:
                io.displayPacket(ble.BLEReadByTypeResponse(attributes=response))
                self.a2mEmitter.sendp(ble.BLEReadByTypeResponse(attributes=response))
            else:
                self.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x08,ecode=response, handle=packet.startHandle))
        return False

    def onMasterFindInformationRequest(self,packet):
        io.info("Find Information Request : startHandle = "+hex(packet.startHandle)+
            " / endHandle = "+hex(packet.endHandle))
        io.info("Response from MITM FindInfo ...")
        (success,response) = self.server.findInformation(packet.startHandle,packet.endHandle)
        if success:
            io.displayPacket(ble.BLEFindInformationResponse(attributes=response))
            self.a2mEmitter.sendp(ble.BLEFindInformationResponse(attributes=response))
        else:
            self.a2mEmitter.sendp(ble.BLEErrorResponse(request=0x04,ecode=response,handle=packet.startHandle))
        return False

    # Check if . is authorized/banned in firewall rules
    def __firewallParser(self, rule):
        pass

    # Import ATT Config file
    def __importATT(self, filename="ATT_SLAVE_MITM"):
        io.info("Importing ATT layer datas from "+filename+" ...")
        attributes = []
        config = configparser.ConfigParser()
        config.read(filename)
        for handle in config.sections():
            attHandle = int(handle,16)
            infos = config[handle]
            attType = infos.get("type")
            attValue = bytes.fromhex(infos.get("value") if infos.get("value") is not None else "")
            # Filter should go there
            self.server.addAttribute(handle=attHandle,value=attValue,type=attType,permissions=["Read","Write"])
        return False

    # Import GATT Config file 
    def __importGATT(self, filename="GATT_SLAVE_MITM"):
        io.info("Importing GATT layer datas from "+filename+" ...")        
        config = configparser.ConfigParser()
        config.read(filename)
        for element in config.sections():
            infos=config[element]
            if "type" in infos:
                print(infos.get('type'))
                if infos.get("type") == "service":
                    io.info("Services ! !")
                    startHandle = int(element,16)
                    endHandle = int(infos.get("endhandle"),16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    if infos.get("servicetype") == "primary":
                        self.server.addPrimaryService(uuid,startHandle)
                    else:
                        self.server.addSecondaryService(uuid,startHandle)
                elif infos.get("type") == "characteristic":
                    declarationHandle = int(element,16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    valueHandle = int(infos.get("valuehandle"),16)
                    value = bytes.fromhex(infos.get("value"))
                    permissions = infos.get("permissions").split(",")
                    self.server.addCharacteristic(uuid,value,declarationHandle,valueHandle,permissions)
                elif infos.get("type") == "descriptor":
                    handle = int(element, 16)
                    uuid = bytes.fromhex(infos.get("uuid"))
                    value = bytes.fromhex(infos.get("value"))
                    self.server.addDescriptor(uuid,value,handle)
        return False
        

    def __fileExists(self,filename):
        return os.path.isfile(filename)

    # Initialise server GATT and run it
    def __setGattServer(self, GATT_SLAVE_FILE, ATT_SLAVE_FILE):
        # init server
        self.server = ble.GATT_Server()
        firewallGattServer = Firewall_GattServer()
        #initParsing
        io.info("Started Parsing")
        checkRules("/Users/ahmed/mirage/mirage/tables/ble_tables.txt")
        io.info("Checking Global Vars")
        print(characteristicRules)
        print(descriptorRules)
        print(serviceRules)
        print(attributeRules)
        io.info("Finished checking Global Vars")
        io.info("MITM: Starting MITM ATT / GATT ... ")
        if ATT_SLAVE_FILE != "" and self.__fileExists(ATT_SLAVE_FILE):
            io.info("MITM: Importing ATT_SLAVE structure")
            firewallGattServer.importATT(forbiddenAtrributes=attributeRules,replaceList=gatt_modifier_rules,server=self.server)
            print('finishing import ATT')
            #self.__importATT(ATT_SLAVE_FILE)
        elif GATT_SLAVE_FILE != "" and self.__fileExists(GATT_SLAVE_FILE):
            io.info("MITM: Importing GATT_SLAVE structure")
            #self.__importGATT(GATT_SLAVE_FILE)
            firewallGattServer.importGATT(forbiddenServices=serviceRules,forbiddenCharacteristics=characteristicRules,forbiddenDescriptors=descriptorRules,server=self.server)
            print('finishing import GATT')
        else:
            io.info("MITM: No filename provided : empty database !")

    # Export heart of the function here 
    def __getGattSlave(self, GATT_SLAVE_FILE, ATT_SLAVE_FILE):
        # Load module
        m = utils.loadModule('ble_discover')
        # Set parameters
        m["WHAT"] = "all"
        m['INTERFACE'] = self.args['INTERFACE1']
        m["START_HANDLE"] = "0x0001"
        m["END_HANDLE"] = "0xFFFF"
        m["FILTER_BY"] = ""
        m["FILTER"] = ""
        m['GATT_FILE']=GATT_SLAVE_FILE
        open(m['GATT_FILE'], 'w').close()
        # Execute to fill GATT_FILE
        m.execute()

        m["WHAT"] = "attributes"
        m['ATT_FILE']=ATT_SLAVE_FILE
        open(m['ATT_FILE'], 'w').close()
        # Execute to fill ATT_FILE
        m.execute()

    def onSlaveConnect(self, initiatorType="public"):
        # Entering the GATT Entering Cloning mode
        while (self.a2sEmitter.getMode() != "NORMAL"):
            utils.wait(seconds=1)
            print(self.a2sEmitter.getMode())
            
        address = utils.addressArg(self.args["TARGET"])
        connectionType = self.args["CONNECTION_TYPE"]
        self.responderAddress = address
        self.responderAddressType = (b"\x00" if self.args["CONNECTION_TYPE"] == "public" else b"\x01")

        io.info("MITM: Connecting to slave "+address+"...")
        self.a2sEmitter.sendp(ble.BLEConnect(dstAddr=address, type=connectionType, initiatorType=initiatorType))

        while not self.a2sEmitter.isConnected(): utils.wait(seconds=0.5)

        # If conneced correctly, then clone the GATT Server
        if self.a2sEmitter.isConnected():
            io.success("Connected on slave : "+self.a2sReceiver.getCurrentConnection())
            
            io.info("MITM: Cloning GATT Server / ATT Attributes ... ")
            self.__getGattSlave("GATT_SLAVE_MITM", "ATT_SLAVE_MITM")
            io.success("MITM: Cloning has been finished ... ")
            io.info("MITM: GATT/ATT starting server ...")
            self.__setGattServer("GATT_SLAVE_MITM", "ATT_SLAVE_MITM")
            io.success("MITM: GATT/ATT server running ... ")
        else:
            io.fail("MITM: No active connections !") 

        return False