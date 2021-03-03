from mirage.core import scenario, interpreter
from mirage.libs import io, ble, bt, utils
CONST_SEND_COMMAND_MASTER = "onMasterWriteBipCommand"

class mitm_test(scenario.Scenario):
    #dict used to count occurences of a packet
    countEvent = {}

    def onStart(self):
        self.a2sEmitter = self.module.a2sEmitter
        self.a2sReceiver = self.module.a2sReceiver
        self.a2mEmitter = self.module.a2mEmitter
        self.a2mReceiver = self.module.a2mReceiver
        io.info("MITM started !")
        return True

    def onMasterWriteCommand(self, packet):
      # If we send a notification from phone to device
        if packet.handle == 0x29 and 0x2 in packet.value:
            io.info("Try to block notification from mobile to device")
            #We add 1 to counter for this type of message
            self.__addEventCounter(CONST_SEND_COMMAND_MASTER)
            #Blocking works but still have
#           if self.countEvent[CONST_SEND_COMMAND_MASTER] > 1 :
#            self.a2mEmitter.sendp(ble.BLEHandleValueNotification(handle=0x25, value=1))
            # We drop packet
            return False
        # If we want to send a message to device to shut up
        elif packet.handle == 0x29 and 0x0 in packet.value:
            io.info("Send shutup command")
            # If notification from phone to device has been sent, then we put the counter of notification to 0
            if self.countEvent[CONST_SEND_COMMAND_MASTER] > 0 :
              return self.__drop(CONST_SEND_COMMAND_MASTER)
            # We authorize
            return False
        # We allow everything else
        else:
            io.info("Unknown command send from master")
            return True

    def onSlaveHandleValueNotification(self, packet):
        #If device sends a notification to phone
        if packet.handle == 0x25 and 0x1 in packet.value:
          #TODO : Put a thread safe way to increments and manage time window
            #We add 1 to counter for this type of message
            self.__addEventCounter(self.onSlaveHandleValueNotification.__name__)
            #If we have 2 messages sent or more (-> message used to say to phone that he has to bell), we send an error
            if self.countEvent[self.onSlaveHandleValueNotification.__name__] >= 2:
                #Send Error To Slave (optionnal)
                self.a2sEmitter.sendp(ble.BLEErrorResponse(handle=packet.handle))
                #Drop Packet, master will receive nothing
                return self.__drop(self.onSlaveHandleValueNotification.__name__)
            else:
                #We allow a single packet to pass
                return True
        else:
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