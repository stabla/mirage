from mirage.libs.ble_utils.constants import COUNTER_FIELD, TIMESTAMP_FIELD
from mirage.libs.ble_utils import constants
import datetime

class FirewallEventManager:

    def __init__(self, eventCounter: dict = {}):
        self.eventCounter = eventCounter

    def resetCounters(self, eventName: str):
        self.eventCounter[eventName][COUNTER_FIELD] = 0
        self.eventCounter[eventName][TIMESTAMP_FIELD] = datetime.datetime.now()

    def initCounters(self, eventName: str):
        if(eventName not in self.eventCounter):
            self.eventCounter[eventName] = {}
            self.resetCounters(eventName)

    def countEvent(self, eventName: str):
        self.eventCounter[eventName][constants.COUNTER_FIELD] += 1
        self.eventCounter[eventName][constants.TIMESTAMP_FIELD] = datetime.datetime.now()

    def durationSinceLastPacket(self, eventName: str):
        delta = datetime.datetime.now()-self.getLastPacketTimestamp(eventName)
        return delta.seconds

    def getCurrentCount(self, eventName: str):
        return self.eventCounter[eventName][constants.COUNTER_FIELD]

    def getLastPacketTimestamp(self, eventName: str):
        return self.eventCounter[eventName][constants.TIMESTAMP_FIELD]

    def printEvent(self,eventName:str):
        print(eventName)
        print(self.getCurrentCount(eventName))
        print(self.durationSinceLastPacket(eventName))