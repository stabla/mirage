from mirage.core import scenario, interpreter
from mirage.libs import io, ble, bt, utils

class firewall(scenario.Scenario):
    #dict used to count occurences of a packet
    countEvent = {}

    def onStart(self):
        self.a2sEmitter = self.module.a2sEmitter
        self.a2sReceiver = self.module.a2sReceiver
        self.a2mEmitter = self.module.a2mEmitter
        self.a2mReceiver = self.module.a2mReceiver
        return True
    
    def onMasterWriteCommand (self,packet):
        if packet.handle == 0x29 and 0x2 in packet.value:
            return True
        if packet.handle == 0x29 and 0x0 in packet.value:
            return False
        else :
            return True
    
    def onSlaveHandleValueNotification (self,packet):
        if packet.handle == 0x25 and 0x1 in packet.value:
            return False
        else :
            return True
    
    def onEnd(self):
        io.info("MITM started")
        return True

    #drop packets and reset counter of packets after drops
    def __drop(self,name: str):
        io.info("According to our firewall policy we choose to drop the packet")
        self.countEvent[name] = 0
        return False
    
    #add packets to event counter
    def __addEventCounter(self,name: str):
        if(name not in self.countEvent):
            self.countEvent[name] = 0
        self.countEvent[name] += 1
