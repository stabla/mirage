from mirage.core import scenario, interpreter, module
from mirage.libs import io, ble, bt, utils
import configparser,os.path,subprocess

class mitm_test(scenario.Scenario):
    
     
    initiatorSecureConnections = True
    initiatorOoB = None
    initiatorMiTm = None
    initiatorMinKeySize =  16
    initiatorInputOutputCapability = None
    
    # Pairing Methods
    secureConnections = None
    useOoB = None
    pairingMethod = None

    def checkSecureConnection(self, packet, responder=False):
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        flag = 'secureConnections'
        if flag in authPaquet.content:
            ruleOK = False
            if not responder:
                ruleOK = self.initiatorSecureConnections in (authPaquet.content[flag], None)
                self.initiatorSecureConnections = authPaquet.content[flag]
            else:
                ruleOK = self.responderSecureConnections in (authPaquet.content[flag], None)
                self.responderSecureConnections = authPaquet.content[flag]
            io.info('LE SecureConnection pairing {0}accepted'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
            else:
                return True
        else:
            io.info('No {0} info on this packet... ending the scenario'.format(
                flag))
            return False

    def checkMiTMRule(self, packet, responder=False):
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        flag = 'mitm'
        if flag in authPaquet.content:
            ruleOK = False
            if not responder:
                ruleOK = self.initiatorMiTm in (authPaquet.content[flag], None)
                self.initiatorMiTm = authPaquet.content[flag]
            else:
                ruleOK = self.responderMiTm in (authPaquet.content[flag], None)
                self.responderMiTm = authPaquet.content[flag]
            io.info('Mitm protection is {0}activated'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
            else:
                return True
        else:
            io.info('No {0} info on this packet... ending the scenario'.format(
                flag))
            return False

    def checkOoB(self, packet, responder=False):
        # Check OoB
        if hasattr(packet, 'outOfBand'):
            ruleOK = False
            if not responder:
                ruleOK = self.initiatorOoB in (packet.outOfBand, None)
                self.initiatorOoB = packet.outOfBand
            else:
                ruleOK = self.responderOoB in (packet.outOfBand, None)
                self.responderOoB = packet.outOfBand
            io.info('OoB pairing rule is {0}accepted'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
            else:
                return True
        else:
            io.info('No outOfBand on this packet... ending the scenario')
            return False

    def checkSizeRule(self, packet, responder=False):
        if hasattr(packet, 'maxKeySize'):
            ruleOK = False
            if not responder:
                ruleOK = self.initiatorMinKeySize >= packet.maxKeySize
                self.initiatorMinKeySize = packet.maxKeySize
            else:
                ruleOK = self.responderMinKeySize >= packet.maxKeySize
                self.responderMinKeySize = packet.maxKeySize
            io.info('maxKeySize pairing rule is {0}accepted'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
            else:
                return True
        else:
            io.info('No {0} on this packet... ending the scenario'.format(
                'maxKeySize'))
            return False

    def pairingMethodSelection(self):
        self.secureConnections = self.responderSecureConnections and self.initiatorSecureConnections
        if self.secureConnections:
            io.info("Both devices supports LE secure connections")
            self.useOOB = self.initiatorOoB and self.responderOoB
            ioCapabilities = self.responderMiTm or self.initiatorMiTm
            self.justWorks = not self.responderMiTm and not self.initiatorMiTm

        else:
            io.info(
                "At least one of the devices doesn't support LE secure connections"
            )
            self.useOOB = self.initiatorOoB or self.responderOoB
            #TODO : Put back
            ioCapabilities = False
            justWorks = not self.responderMiTm and not self.initiatorMiTm

        io.chart(["Out Of Bond", "IO Capabilities", "Just Works"], [[
            "yes" if self.useOOB else "no", "yes" if ioCapabilities else "no",
            "yes" if justWorks else "no"
        ]])

        if ioCapabilities:
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
                secureConnections=self.secureConnections,
                initiatorInputOutputCapability=initiator,
                responderInputOutputCapability=responder)

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
        io.info("MITM started !")

    def onEnd(self):
        io.info("MITM finished")

    
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
        checkSecureConnectionRuleOK =  self.checkSecureConnection(packet)
        #Check OoB
        checkOoBRuleOK = self.checkOoB(packet)
        # Check minKeySize
        checkSizeRuleOK = self.checkSizeRule(packet)
        checkMitmRuleOK = self.checkMiTMRule(packet)
        return checkSecureConnectionRuleOK and checkOoBRuleOK and checkSizeRuleOK and checkMitmRuleOK
        

    # Drop packets and reset counter of packets after drops
    def __drop(self, name: str):
        io.info("According to our firewall policy we choose to drop the packet")
        self.firewallManager.resetCounters(name)
        return False

    def getEventName(self, handle: hex, value: hex, handlerName: str):
        return "{0}_{1}_{2} ".format(str(handle),str(value),handlerName)