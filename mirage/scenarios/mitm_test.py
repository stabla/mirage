from mirage.core import scenario, interpreter, module
from mirage.libs import io, ble, bt, utils
from mirage.libs.ble_utils.firewall import *
import configparser,os.path,subprocess

class mitm_test(scenario.Scenario):
    
    #Policies
    LeSecureConnectionAuthorized = False
    OoBAuthorized = False
    minKeySizeAuthorized = 16
    MiTmProtectionActivated = False

    # Secure connection vars
    initiatorSecureConnections = None
    responderSecureConnections = None
    secureConnections = None

    # OoB
    initiatorOoB = None
    responderOoB = None
    useOoB = None

    # MiTm
    initiatorMiTm = None
    responderMiTm = None

    #MinKeySize
    initiatorMinKeySize = None
    responderMinKeySize = None

    # Iocap
    initiatorInputOutputCapability = None
    responderInputOutputCapability = None

    # Auth Methods
    ioCapabilities = None
    justWorks = None
    pairingMethod = None    

    def checkSecureConnection(self, packet, responder=False):
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        flag = 'secureConnections'
        if flag in authPaquet.content:
            ruleOK = (authPaquet.content[flag] == self.LeSecureConnectionAuthorized)
            print('LE SecureConnection pairing {0}accepted'.format(
                '' if ruleOK else 'not '))
            if responder == False:
                self.initiatorSecureConnections = authPaquet.content[flag]
            else:
                self.responderSecureConnections = authPaquet.content[flag]
            if not ruleOK:
                return False
        else:
            print('No {0} info on this packet... ending the scenario'.format(flag))
            return False
    
    def checkMiTMRule(self, packet, responder=False):
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        flag = 'mitm'
        if flag in authPaquet.content:
            ruleOK = (authPaquet.content[flag] == self.MiTmProtectionActivated)
            print('Mitm protection is {0}activated'.format(
                '' if ruleOK else 'not '))
            if responder == False:
                self.initiatorMiTm = authPaquet.content[flag]
            else:
                self.responderMiTm = authPaquet.content[flag]
            if not ruleOK:
                return False
        else:
            print('No {0} info on this packet... ending the scenario'.format(flag))
            return False

    def checkOoB(self, packet, responder=False):
        # Check OoB
        if hasattr(packet, 'outOfBand'):
            ruleOK = (packet.outOfBand == self.OoBAuthorized)
            print('OoB pairing rule is {0}accepted'.format(
                '' if ruleOK else 'not '))
            if responder == False:
                self.initiatorOoB = packet.outOfBand
            else:
                self.responderOoB = packet.outOfBand
            if not ruleOK:
                return False
        else:
            print('No outOfBand on this packet... ending the scenario')
            return False


    def checkSizeRule(self, packet, responder=False):
        if hasattr(packet, 'maxKeySize'):
            ruleOK = self.minKeySizeAuthorized >= packet.maxKeySize
            print('maxKeySize pairing rule is {0}accepted'.format(
                '' if ruleOK else 'not '))
            if responder == False:
                self.initiatorMinKeySize = packet.maxKeySize
            else:
                self.responderMinKeySize = packet.maxKeySize
            if not ruleOK:
                return False                
        else:
            print('No {0} on this packet... ending the scenario'.format('maxKeySize'))
            return False
    def pairingMethodSelection(self):
        self.secureConnections = self.responderSecureConnections and self.initiatorSecureConnections
        if self.secureConnections:
            io.info("Both devices supports LE secure connections")
            self.useOOB = self.initiatorOoB and self.responderOoB
            self.ioCapabilities = self.responderMiTm or self.initiatorMiTm
            self.justWorks = not self.responderMiTm and not self.initiatorMiTm

        else:
            io.info(
                "At least one of the devices doesn't support LE secure connections")
            self.useOOB = self.initiatorOoB or self.responderOoB
            #TODO : Put back
            self.ioCapabilities = False
            self.justWorks = not self.responderMiTm and not self.initiatorMiTm

        io.chart(["Out Of Bond", "IO Capabilities", "Just Works"],
                 [
            ["yes" if self.useOOB else "no",
                "yes" if self.ioCapabilities else "no",
                "yes" if self.justWorks else "no"
             ]])

        if self.ioCapabilities:
            initiator = "NoInputNoOutput"
            responder = "NoInputNoOutput"
            if self.initiatorInputOutputCapability.data[0] == 0x00:
                initiator = "DisplayOnly"
            elif self.initiatorInputOutputCapability.data[0] == 0x01:
                initiator = "DisplayYesNo"
            elif self.initiatorInputOutputCapability.data[0] == 0x02:
                initiator = "KeyboardOnly"
            elif self.initiatorInputOutputCapability.data[0] == 0x03:
                initiator = "NoInputNoOutput"
            elif self.initiatorInputOutputCapability.data[0] == 0x04:
                initiator = "KeyboardDisplay"

            if self.responderInputOutputCapability.data[0] == 0x00:
                responder = "DisplayOnly"
            elif self.responderInputOutputCapability.data[0] == 0x01:
                responder = "DisplayYesNo"
            elif self.responderInputOutputCapability.data[0] == 0x02:
                responder = "KeyboardOnly"
            elif self.responderInputOutputCapability.data[0] == 0x03:
                responder = "NoInputNoOutput"
            elif self.responderInputOutputCapability.data[0] == 0x04:
                responder = "KeyboardDisplay"

            pairingMethod = ble.PairingMethods.getPairingMethod(
                secureConnections=self.secureConnections, initiatorInputOutputCapability=initiator, responderInputOutputCapability=responder)

            if pairingMethod == ble.PairingMethods.JUST_WORKS:
                self.pairingMethod = "JustWorks"
            elif pairingMethod == ble.PairingMethods.PASSKEY_ENTRY:
                self.pairingMethod = "PasskeyEntry"
            elif pairingMethod == ble.PairingMethods.NUMERIC_COMPARISON:
                self.pairingMethod = "NumericComparison"
            else:
                self.pairingMethod = "JustWorks"
        elif self.useOOB:
            self.pairingMethod = "OutOfBond"
        else:
            self.pairingMethod = "JustWorks"
                
    

    def onStart(self):
        self.a2sEmitter = self.module.a2sEmitter
        self.a2sReceiver = self.module.a2sReceiver
        self.a2mEmitter = self.module.a2mEmitter
        self.a2mReceiver = self.module.a2mReceiver
        self.firewallManager = FirewallEventManager()
        self.dependencies = ["ble_discover"] # for GATT
        io.info("MITM started !")

       # Load module
        self.m = utils.loadModule('ble_discover')
        self.m['INTERFACE'] = self.args['INTERFACE1']
        self.m["START_HANDLE"] = "0x0001"
        self.m["END_HANDLE"] = "0xFFFF"
        self.m["FILTER_BY"] = ""
        self.m["FILTER"] = ""

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
        else : #default case of the rule
            return self.__drop(currentEvent)
        
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
            # packet is allowed
            return True
        else : #default case of the rule
            return self.__drop(currentEvent)
        

    def onMasterPairingRequest(self,packet):
        # Check if we accept use LeSecureConnections or Legacy
        self.checkSecureConnection(packet)
        #Check OoB
        self.checkOoB(packet)
        # Check minKeySize
        self.checkSizeRule(packet)
        self.checkMiTMRule(packet)

    # Drop packets and reset counter of packets after drops
    def __drop(self, name: str):
        io.info("According to our firewall policy we choose to drop the packet")
        self.firewallManager.resetCounters(name)
        return False

    def getEventName(self, handle: hex, value: hex, handlerName: str):
        return "{0}_{1}_{2} ".format(str(handle),str(value),handlerName)

    """
        MIDDLE FILTERING GATT SERVER 
    """
    # When receiving a packet for GATT
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

    # When receiving a packet for ATT
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

    # NOT USED
    # When receiving a request FindInfo
    #
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

    def onSlaveConnect(self, initiatorType="public"):
        # Entering the GATT Entering Cloning mode
        while (self.a2sEmitter.getMode() != "NORMAL"):
            utils.wait(seconds=1)
            print(self.a2sEmitter.getMode())
            
        # Verify the connection type
        address = utils.addressArg(self.args["TARGET"])
        connectionType = self.args["CONNECTION_TYPE"]
        self.responderAddress = address
        self.responderAddressType = (b"\x00" if self.args["CONNECTION_TYPE"] == "public" else b"\x01")

        # Connecting to Slave
        io.info("MITM: Connecting to slave "+address+"...")
        self.a2sEmitter.sendp(ble.BLEConnect(dstAddr=address, type=connectionType, initiatorType=initiatorType))

        # Wait until connection
        while not self.a2sEmitter.isConnected(): utils.wait(seconds=0.5)

        # When connected, clone the GATT Server
        if self.a2sEmitter.isConnected():
            io.success("Connected on slave : "+self.a2sReceiver.getCurrentConnection())
            # Cloning the ATT
            io.info("MITM: Cloning Slave's ATT Server ...")
            self.__getAttSlave("ATT_SLAVE_MITM")
            # Cloning the GATT
            io.info("MITM: Cloning GATT Server ... ")
            self.__getGattSlave("GATT_SLAVE_MITM")
            io.success("MITM: Cloning has been finished ... ")
            # Starting the server
            io.info("MITM: GATT/ATT starting server ...")
            self.__setGattServer("GATT_SLAVE_MITM", "ATT_SLAVE_MITM")
            io.success("MITM: GATT/ATT server running ... ")
        else:
            io.fail("MITM: No active connections !") 
        return False

    # Check if file exists 
    def __fileExists(self,filename):
        return os.path.isfile(filename)

    # Initialize GATT Server
    def __setGattServer(self, GATT_SLAVE_FILE, ATT_SLAVE_FILE):
        # Init server
        self.server = ble.GATT_Server()
        # Create GattServer object
        firewallGattServer = Firewall_GattServer()
        # InitParsing
        io.info("MITM: Parsing of rules ...")
        (characteristicRules,serviceRules,descriptorRules,attributeRules,gatt_modifier_rules) = checkRules('/Users/ahmed/mirage/mirage/tables/scenario/ble_tables.txt')
        io.info("MITM: Starting MITM ATT / GATT ... ")
        # Import ATT Structure 
        # if ATT_SLAVE_FILE != "" and self.__fileExists(ATT_SLAVE_FILE):
        #     io.info("MITM: Importing ATT_SLAVE structure")
        #     firewallGattServer.importATT(filename=ATT_SLAVE_FILE,forbiddenAtrributes=attributeRules,replaceList=gatt_modifier_rules,server=self.server)
        #     print('finishing import ATT')
        # Import GATT Structure
        if GATT_SLAVE_FILE != "" and self.__fileExists(GATT_SLAVE_FILE):
            io.info("MITM: Importing GATT_SLAVE structure")
            firewallGattServer.importGATT(filename=GATT_SLAVE_FILE,forbiddenServices=serviceRules,forbiddenCharacteristics=characteristicRules,forbiddenDescriptors=descriptorRules,server=self.server)
            print('finishing import GATT')
        else:
            io.info("MITM: No filename provided : empty database !")
        #print(self.server.database.show())
        # print("STRUCTURE SERVEUR GATT")
        # print(self.server.database.showGATT())

    # Export Slave's ATT Server
    def __getAttSlave(self, ATT_SLAVE_FILE):
        # Set attributes
        self.m["WHAT"] = "attributes"
        self.m['ATT_FILE']=ATT_SLAVE_FILE
        # Empty file before filling
        open(self.m['ATT_FILE'], 'w').close()
        # Execute to fill ATT_FILE
        self.m.execute()

    # Export Slave's GATT
    def __getGattSlave(self, GATT_SLAVE_FILE):
        # Set attributes
        self.m["WHAT"] = "all"
        self.m['GATT_FILE']=GATT_SLAVE_FILE
        # Empty file before filling
        open(self.m['GATT_FILE'], 'w').close()
        # Execute to fill GATT_FILE
        self.m.execute()