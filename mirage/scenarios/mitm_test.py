from mirage.core import scenario, interpreter, module
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
        self.dependencies = ["ble_discover"] # for GATT
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


    """
        GATT CENTRAL

    """
    # Initialise server GATT and run it
    def __setGattServer(self):
        ...

    # Export heart of the function here 
    def __getGattSlave(self):
        ...

    def onSlaveConnect(self, initiatorType="public"):
        # Entering the GATT Entering Cloning mode
        while (self.a2sEmitter.getMode() != "NORMAL"):
            utils.wait(seconds=1)
            print(self.a2sEmitter.getMode())
            
        address = utils.addressArg(self.args["TARGET"])
        connectionType = self.args["CONNECTION_TYPE"]
        self.responderAddress = address
        self.responderAddressType = (b"\x00" if self.args["CONNECTION_TYPE"] == "public" else b"\x01")

        io.info("Connecting to slave "+address+"...")
        self.a2sEmitter.sendp(ble.BLEConnect(dstAddr=address, type=connectionType, initiatorType=initiatorType))

        while not self.a2sEmitter.isConnected(): utils.wait(seconds=0.5)

        # If conneced correctly, then clone the GATT Server
        if self.a2sEmitter.isConnected():
            io.success("Connected on slave : "+self.a2sReceiver.getCurrentConnection())
            io.info("DISCOVER: Cloning GATT Server ")
            # Load module
            m = utils.loadModule('ble_discover')
            # Set parameters
            m["WHAT"] = "all"
            m['INTERFACE'] = self.args['INTERFACE1']
            m["START_HANDLE"] = "0x0001"
            m["END_HANDLE"] = "0xFFFF"
            m["FILTER_BY"] = ""
            m["FILTER"] = ""
            m['GATT_FILE']="GATT_SLAVE_MITM"
            # Clean file - USELESS
            ## open(m['GATT_FILE'], 'w').close()
            # Execute to fill GATT_FILE
            m.execute()

            # Clean file - USELESS
            # Execute to fill ATT_FILE
            ## open(m['ATT_FILE'], 'w').close()
            m["WHAT"] = "attributes"
            m['ATT_FILE']="ATT_SLAVE_MITM"
            m.execute()


        else:
            io.fail("No active connections !") 
        
        return False