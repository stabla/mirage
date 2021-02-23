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

  def onMasterWriteRequest(self,packet):
    logger("Write Request is received (from master)",packet)

  def onSlaveWriteRequest(self,packet):
    logger("Write Request is received (from slave)",packet)

  def onMasterReadRequest(self,packet):
    logger("Read Request is received (from master)",packet)

  def onMasterReadBlobRequest(self,packet):
    logger("Read Blob Request (from master) ",packet)
    return drop()

  def onSlaveReadBlobResponse(self,packet):
    logger("Read Blob Response (from slave)",packet)
    return drop()

  def onEnd(self):
    io.info("MITM started")

  def onMasterReadByGroupTypeRequest(self,packet):
    logger("Read By Group Type Request (from master)",packet)
  
  def onSlaveReadByGroupTypeResponse(self,packet):
    logger("Read By Group Type Response (from slave)",packet)

  def onMasterReadByTypeRequest(self,packet):
    logger("Read By Type Request (from master)",packet)
  
  def onSlaveReadByTypeResponse(self,packet):
    logger("Read By Type Response (from slave)",packet)

  def onMasterFindByTypeValueRequest(self,packet):
      logger("Find Type By Value Request (from master)",packet)

  def onSlaveFindByTypeValueResponse(self,packet):
    logger("Find Type By Value Response (from slave)",packet)

    #Remaining Signal to manage
      # onMasterExchangeMTURequest
      # onSlaveExchangeMTUResponse
      # onSlaveErrorResponse
      # onSlaveHandleValueNotification
      # onSlaveHandleValueIndication
      # onMasterHandleValueConfirmation
      # onMasterFindInformationRequest
      # onSlaveFindInformationResponse
      # onMasterPairingRequest
      # onSlavePairingResponse
      # onMasterPairingConfirm
      # onSlavePairingConfirm
    