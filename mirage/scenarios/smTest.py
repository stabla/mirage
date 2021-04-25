from mirage.core import scenario
from mirage.libs import io, ble, esb, utils


class smTest(scenario.Scenario):
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

    def printSummary(self):
        print('begin List')
        print('LeSecureConnectionAuthorized '+ str(self.LeSecureConnectionAuthorized))
        print('OoBAuthorized '+ str(self.OoBAuthorized))
        print('minKeySizeAuthorized ' + str(self.minKeySizeAuthorized))
        print('initiatorSecureConnections ' + str(self.initiatorSecureConnections))
        print('responderSecureConnections ' + str(self.responderSecureConnections))
        print('secureConnections ' + str(self.secureConnections))
        print('initiatorOoB ' + str(self.initiatorOoB))
        print('responderOoB ' + str(self.responderOoB))
        print('useOoB ' + str(self.useOoB))
        print('initiatorMiTm ' + str(self.initiatorMiTm))
        print('responderMiTm ' + str(self.responderMiTm))
        print('initiatorMinKeySize ' + str(self.initiatorMinKeySize))
        print('responderMinKeySize ' + str(self.responderMinKeySize))
        print('initiatorInputOutputCapability ' + str(self.initiatorInputOutputCapability))
        print('responderInputOutputCapability ' + str(self.responderInputOutputCapability))
        print('ioCapabilities ' + str(self.ioCapabilities))
        print('justWorks ' + str(self.justWorks))
        print('pairing Method ' + str(self.pairingMethod))
        

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
        print('Mitm Started')

    def onEnd(self):
        print('Mitm Finished')

    def onMasterPairingRequest(self, packet):
        print('Pairing from master sent')
        # Check if master wants to use LeSecureConnections or Legacy
        self.checkSecureConnection(packet)
        #Check OoB
        self.checkOoB(packet)
        # Check minKeySize
        self.checkSizeRule(packet)
        self.checkMiTMRule(packet)

    def onSlavePairingResponse(self, packet):
        # Check if master wants to use LeSecureConnections or Legacy
        self.checkSecureConnection(packet,True)
        #Check OoB
        self.checkOoB(packet,True)
        # Check minKeySize
        self.checkSizeRule(packet,True)
        self.checkMiTMRule(packet,True)
        self.pairingMethodSelection()
        self.printSummary()
