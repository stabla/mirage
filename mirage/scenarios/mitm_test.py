from mirage.core import scenario, interpreter, module
from mirage.libs import io, ble, bt, utils
import configparser,os.path,subprocess

class mitm_test(scenario.Scenario):
    

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
        if packet.handle == 0xd and 0x3 in packet.value:
            #Increment counter of one packet and update timestamp of last packet that comes
            self.firewallManager.countEvent(currentEvent)
            # packet is allowed
            return True
        else : #default case of the rule
            return True 

    # Drop packets and reset counter of packets after drops
    def __drop(self, name: str):
        io.info("According to our firewall policy we choose to drop the packet")
        self.firewallManager.resetCounters(name)
        return False

    def getEventName(self, handle: hex, value: hex, handlerName: str):
        return "{0}_{1}_{2} ".format(str(handle),str(value),handlerName)