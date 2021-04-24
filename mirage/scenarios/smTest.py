from mirage.core import scenario
from mirage.libs import io, ble, esb, utils


class smTest(scenario.Scenario):
    LeSecureConnection = False

    def onMasterPairingRequest(self, packet):
        print('Pairing from master sent')
        #Check if master wants to use LeSecureConnections or Legacy
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        print('authPaquetFlag dissected OK :')
        print(authPaquet.content)
        if authPaquet.content.__contains__('secureConnections') and not authPaquet.content['secureConnections']:
            print('LE SecureConnection pairing not accepted')
            pass
        else :
            print('LE SecureConnection Pairing accepted')
            self.LeSecureConnection =True
        print('Let\'s see what slave can do')

    def onSlavePairingResponse(self, packet):
        print('Pairing from slave sent')
        authPaquet = ble.AuthReqFlag(data=bytes([packet.authentication]))
        print('authPaquetFlag dissected OK :')
        print(authPaquet.content)
        if authPaquet.content.__contains__('secureConnections') and authPaquet.content['secureConnections']:
            print('Slave can support LeSecureConnection, if master support LE SecureConnection pairing authorized')
            if self.LeSecureConnection: 
                print('master support LeSecureConnection')
            else : 
                print('master doesn\'t support LeSecureConnection')
            return False
        else :
            print('Slave can\'t support LeSecureConnection, pairing denied')
            return False
            


    def onStart(self):
        print('Mitm Started')

    def onEnd(self):
        print('Mitm Finished')

    def onKey(self, key):
        return True
