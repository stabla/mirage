from mirage.core import scenario, interpreter, module
from mirage.libs import io, ble, bt, utils
from mirage.libs.ble_utils.firewall import *

class mitm_test(scenario.Scenario):
    

    def onStart(self):
        self.a2sEmitter = self.module.a2sEmitter
        self.a2sReceiver = self.module.a2sReceiver
        self.a2mEmitter = self.module.a2mEmitter
        self.a2mReceiver = self.module.a2mReceiver
        self.firewallManager = FirewallEventManager()
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
            #Check if flow of packets is allowed or not
            if self.firewallManager.getCurrentCount(currentEvent) >= 2 and sinceLastEventDuration < WINDOW_SIZE_IN_SECONDS:
                return self.__drop(currentEvent)
            elif sinceLastEventDuration > WINDOW_SIZE_IN_SECONDS: # After a certain time counters go down
                self.firewallManager.resetCounters(currentEvent)
            else: # number of packet flows is inferior of limit during window
                return True

    # Drop packets and reset counter of packets after drops
    def __drop(self, name: str):
        io.info("According to our firewall policy we choose to drop the packet")
        self.firewallManager.resetCounters(name)
        return False

    def getEventName(self, handle: hex, value: hex, handlerName: str):
        return "{0}_{1}_{2} ".format(str(handle),str(value),handlerName)