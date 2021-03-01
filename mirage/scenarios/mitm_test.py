from mirage.core import scenario
from mirage.libs import io,ble,bt,utils

	
def logger(name,packet):
  io.info("SCENARIO: Signal comes from " + name)
  packet.show()

def drop():
    io.info("According to our firewall policy we choose to drop the packet")
    return False
    
class mitm_test(scenario.Scenario):
  def onStart(self):
    self.a2sEmitter = self.module.a2sEmitter 
    self.a2sReceiver = self.module.a2sReceiver
    self.a2mEmitter = self.module.a2mEmitter
    self.a2mReceiver = self.module.a2mReceiver 
    io.info("MITM started !")

  def onMasterWriteCommand(self,packet):
    if packet.handle == 0x29 and 0x2 in packet.value:
      io.info("End Bip command send from master")
      #Not necessarry finally just never send the request
      #self.a2sEmitter.sendp(ble.BLEErrorResponse(handle=packet.handle))
      return False
    elif packet.handle == 0x25 and 0x0 in packet.value:
      io.info("Shut Bip command send from master")
    else:
      io.info("Unknown command send from master")

  def onSlaveHandleValueNotification(self,packet):
    if packet.handle == 0x25 and 0x1 in packet.value:
      packet.show()
      io.info("Notification send from slave")
      #Drop notifications from slave
      self.a2mEmitter.sendp(ble.BLEErrorResponse(handle=packet.handle))
      return False

  def onEnd(self):
    io.info("MITM started")