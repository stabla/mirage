from mirage.core import scenario
from mirage.libs import io, ble, esb, utils


class smTest(scenario.Scenario):

    #Initatior (BLE Pairing request)
    initiatorSecureConnections = False
    initiatorOoB = False
    initiatorMiTm = False
    initiatorMinKeySize = 16
    initiatorInputOutputCapability = None

    #Responder (BLE Pairing response)
    responderSecureConnections = False
    responderOoB = False
    responderMiTm = False
    responderMinKeySize = 16
    responderInputOutputCapability = None

    # Pairing Methods
    secureConnections = None
    useOoB = None
    pairingMethod = None

    def printSummary(self):
        print('begin List')
        print('initiatorSecureConnections ' +
              str(self.initiatorSecureConnections))
        print('initiatorOoB ' + str(self.initiatorOoB))
        print('initiatorMiTm ' + str(self.initiatorMiTm))
        print('initiatorMinKeySize ' + str(self.initiatorMinKeySize))
        print('initiatorInputOutputCapability ' +
              str(self.initiatorInputOutputCapability))
        print('responderSecureConnections ' +
              str(self.responderSecureConnections))
        print('responderOoB ' + str(self.responderOoB))
        print('responderMiTm ' + str(self.responderMiTm))
        print('responderMinKeySize ' + str(self.responderMinKeySize))
        print('responderInputOutputCapability ' +
              str(self.responderInputOutputCapability))
        print('secureConnections ' + str(self.secureConnections))
        print('useOoB ' + str(self.useOoB))
        print('pairing Method ' + str(self.pairingMethod))

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
        self.checkSecureConnection(packet, True)
        #Check OoB
        self.checkOoB(packet, True)
        # Check minKeySize
        self.checkSizeRule(packet, True)
        self.checkMiTMRule(packet, True)
        self.pairingMethodSelection()
        self.printSummary()

    def checkSecureConnection(self, packet, responder=False):
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        flag = 'secureConnections'
        if flag in authPaquet.content:
            ruleOK = False
            if not responder:
                ruleOK = authPaquet.content[
                    flag] == self.initiatorSecureConnections
                self.initiatorSecureConnections = authPaquet.content[flag]
            else:
                ruleOK = authPaquet.content[
                    flag] == self.responderSecureConnections
                self.responderSecureConnections = authPaquet.content[flag]
            print('LE SecureConnection pairing {0}accepted'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
        else:
            print('No {0} info on this packet... ending the scenario'.format(
                flag))
            return False

    def checkMiTMRule(self, packet, responder=False):
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        flag = 'mitm'
        if flag in authPaquet.content:
            ruleOK = False
            if not responder:
                ruleOK = authPaquet.content[flag] == self.initiatorMiTm
                self.initiatorMiTm = authPaquet.content[flag]
            else:
                ruleOK = authPaquet.content[flag] == self.responderMiTm
                self.responderMiTm = authPaquet.content[flag]
            print('Mitm protection is {0}activated'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
        else:
            print('No {0} info on this packet... ending the scenario'.format(
                flag))
            return False

    def checkOoB(self, packet, responder=False):
        # Check OoB
        if hasattr(packet, 'outOfBand'):
            ruleOK = False
            if not responder:
                ruleOK = packet.outOfBand == self.initiatorOoB
                self.initiatorOoB = packet.outOfBand
            else:
                ruleOK = packet.outOfBand == self.responderOoB
                self.responderOoB = packet.outOfBand
            print('OoB pairing rule is {0}accepted'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
        else:
            print('No outOfBand on this packet... ending the scenario')
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
            print('maxKeySize pairing rule is {0}accepted'.format(
                '' if ruleOK else 'not '))
            if not ruleOK:
                return False
        else:
            print('No {0} on this packet... ending the scenario'.format(
                'maxKeySize'))
            return False