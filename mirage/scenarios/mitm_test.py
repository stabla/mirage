from mirage.core import scenario, interpreter, module
from mirage.libs import io, ble, bt, utils

class mitm_test(scenario.Scenario):
    

    def onStart(self):
        self.a2sEmitter = self.module.a2sEmitter
        self.a2sReceiver = self.module.a2sReceiver
        self.a2mEmitter = self.module.a2mEmitter
        self.a2mReceiver = self.module.a2mReceiver
        io.info("MITM started !")

    def onEnd(self):
        io.info("MITM finished")
    
    def compareCorrectValue(packetType,value):
        if packetType == bytes:
            return bytes.fromhex(value)
        elif packetType == int:
            return int(value)
        else:
            return value

    
    def onMasterWriteCommand(self,packet):
        packetType = type(packet.value)
        valueInFile = self.compareCorrectValue(packetType,'0x2')
        if packet.handle == 0x29 and valueInFile in packet.value :
            # packet is allowed
            return True 
        valueInFile = self.compareCorrectValue(packetType,'0x0')
        if packet.handle == 0x29 and valueInFile in packet.value :
            # packet is allowed
            return True 
        else : #default case of the rule
            return self.__drop(currentEvent,packet)

    def onSlaveHandleValueNotification(self,packet):
        packetType = type(packet.value)
        valueInFile = self.compareCorrectValue(packetType,'0x1')
        if packet.handle == 0x25 and valueInFile in packet.value :
            #Deny packet
            return self.__drop(currentEvent,packet)
        else : #default case of the rule
            return self.__drop(currentEvent,packet)

    def onMasterWriteRequest(self,packet):
        packetType = type(packet.value)
        valueInFile = self.compareCorrectValue(packetType,'6f7171')
        if packet.handle == 0xb and valueInFile in packet.value :
            #Deny packet
            return self.__drop(currentEvent,packet)
        valueInFile = self.compareCorrectValue(packetType,'8f')
        if packet.handle == 0xb and valueInFile in packet.value :
            #Deny packet
            return self.__drop(currentEvent,packet)
        else : #default case of the rule
            return self.__drop(currentEvent,packet)

    # Drop packets and reset counter of packets after drops
    def __drop(self, name: str,packet):
        io.info("According to our firewall policy we choose to drop the following packet")
        io.info(packet)
        return False

    def getEventName(self, handle: hex, value: hex, handlerName: str):
        return "{0}_{1}_{2} ".format(str(handle),str(value),handlerName)