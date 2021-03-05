from mirage.core import scenario, interpreter
from mirage.libs import io, ble, bt, utils
from mirage.libs.ble_utils.firewall import *

class mitm_test(scenario.Scenario):
    # dict used to count occurences of a packet

    def onStart(self):
        self.a2sEmitter = self.module.a2sEmitter
        self.a2sReceiver = self.module.a2sReceiver
        self.a2mEmitter = self.module.a2mEmitter
        self.a2mReceiver = self.module.a2mReceiver
        self.firewallManager = FirewallEventManager()
        io.info("MITM started !")
        return True

    def onMasterWriteCommand(self, packet):
      # If we send a notification from phone to device
        masterNotificationEvent = self.onMasterWriteCommand.__name__
        currentEvent = self.getEventName(packet.handle, packet.value, masterNotificationEvent)
        self.firewallManager.initCounters(currentEvent)
        if packet.handle == 0x29 and 0x2 in packet.value or packet.handle == 0x29 and 0x0 in packet.value:
            self.firewallManager.printEvent(currentEvent)
            return True
        else:
            io.info("Unknown command send from master")
            return self.__drop(currentEvent)

    def onSlaveHandleValueNotification(self, packet):
        slaveNotificationEvent = self.onSlaveHandleValueNotification.__name__
        currentEvent = self.getEventName(packet.handle, packet.value, slaveNotificationEvent)
        self.firewallManager.initCounters(currentEvent)
        sinceLastEventDuration = self.firewallManager.durationSinceLastPacket(currentEvent)
        if packet.handle == 0x25 and 0x1 in packet.value:
            # We add 1 to counter for this type of message
            self.firewallManager.printEvent(currentEvent)
            self.firewallManager.countEvent(currentEvent)
            # If we have 2 messages sent or more (-> message used to say to phone that he has to bell), we block packets
            if self.firewallManager.getCurrentCount(currentEvent) > 2 and sinceLastEventDuration < constants.WINDOW_SIZE_IN_SECONDS:
                # Drop Packet, master will receive nothing, no need to send error message because we sned notification
                return self.__drop(currentEvent)
            elif sinceLastEventDuration > constants.WINDOW_SIZE_IN_SECONDS:
                self.firewallManager.resetCounters(currentEvent)
            else:
                return True
        else:
            return True

    def onEnd(self):
        io.info("MITM started")
        return True

    # drop packets and reset counter of packets after drops
    def __drop(self, name: str):
        io.info("According to our firewall policy we choose to drop the packet")
        self.firewallManager.resetCounters(name)
        return False

    def getEventName(self, handle: hex, value: hex, handlerName: str):
        return "{0}_{1}_{2} ".format(str(handle),str(value),handlerName)



'''
    """
        GATT : Central
    """
    # Import target's GATT Server
    def __initGATTServer(self):
        # Use the exportGATT from ble_discover
        # Read the file, import it here there
            # see ble_save
            # Can use importGATT
        # Analyze content
            # Can use load()
        # Select what we need
            # 
        # Init our GATTServer 
        self.server = ble.GATT_Server()
        ...

    # Import target's ATTs
    def __initATT(self):
        # Use the export attributes from ble_discover
        # Read the output file, import it here
            # See ble_slave
            # Can use importATT
        # Analyze content
            # Can use load()
        # Select what we need
        # Init our ATT
            # Push it to the server

    # Add an ATT to our GATT Server
    def addATT(self):
        # Maybe
        ...

    # GATT Server transmitter
    def runGATT(self):
        # Manage the correspondance between real GATT and this one
        ...
'''
