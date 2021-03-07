from assignedNumbers import AssignedNumbers
import struct,string,copy

class Dissector:
	'''
	This class defines a dissector : it allows to easily convert a complex data structure to the corresponding raw bytes, or the raw bytes to the corresponding data structure. 
	Every dissector must inherits from this class in order to provide the same API.

	A data structure is described as a dictionary, composed of one (or more) field(s) and stored in the ``content`` attribute. Every key of this dictionary can be manipulated as a standard attribute.
	The corresponding data is stored in the ``data`` attribute as a list of raw bytes.

	Two main methods have to be implemented :

	  * **build** : this method converts the data structure to the corresponding raw bytes
	  * **dissect** : this method converts the raw bytes to the corresponding data structure
	'''
	def __init__(self,data=b"",length=-1,content={},*args, **kwargs):
		self.data = data
		if len(args)==1 and data==b"":
			self.data = args[0]
			
		self.length = length if length!=-1 else len(self.data)

		self.content = copy.copy(content)

		if self.data != b"":
			self.dissect()
		else:
			for k,v in kwargs.items():
				self.content[k] = v
		self.build()

	def dissect(self):
		'''
		This method converts the data structure to the corresponding raw bytes.

		:Example:
			
			>>> dissector.dissect()

		'''

		self.content = {}

	def __getattr__(self, name):
		if name in self.content:
			return self.content[name]
		else:
			return None

	def __setattribute__(self,name,value):
		self.content[name] = value
		self.build()

	def __repr__(self):
		return self.__str__()

	def __eq__(self,other):
		return self.data == other.data or self.content == other.content

	def build(self):
		'''
		This method converts the raw bytes to the corresponding data structure.

		:Example:
			
			>>> dissector.build()

		'''

		self.data = b""
		self.length = -1


class UUID(Dissector):
	'''
	This class inherits from ``Dissector``, and allows to quicky and easily use UUID (Universally Unique IDentifier).
	It provides a way to convert them into their multiple forms.
	
	This dissector uses the data structure dictionary in order to use the following fields as simple attributes :
	  * **UUID16** field : UUID (16 bits)
	  * **UUID128** field : UUID (128 bits)
	  * **name** field : name

 	:Example:

		>>> UUID(name="Generic Access").data.hex()
		'1800'
		>>> UUID(data=bytes.fromhex('1800')).name
		'Generic Access'
		>>> UUID(data=bytes.fromhex('1800')).UUID16
		6144
		>>> UUID(data=bytes.fromhex('1800')).UUID128.hex()
		'0000180000001000800000805f9b34fb'
		>>> UUID(data=bytes.fromhex('1801'))
		UUID(128bits:00001801-0000-1000-8000-00805f9b34fb, 16bits:0x1801, name:Generic Attribute )

	'''
	def _correct128(self):
		if "UUID128" in self.content and len(self.content["UUID128"]) == 32:
			self.content["UUID128"] = self.content["UUID128"].replace(b"-",b"").hex()

	def dissect(self):

		if self.length == 2:
			uuid16 = struct.unpack('>H',self.data)[0]
			uuid128 = b"\x00\x00" + self.data + b"\x00\x00\x10\x00\x80\x00\x00\x80\x5F\x9B\x34\xFB"
			name = AssignedNumbers.getNameByNumber(uuid16)
			self.content={"UUID16":uuid16,"UUID128":uuid128,"name":name}
		else:
			uuid = self.data[0:16]
			self.content={"UUID128":uuid}


	def build(self):
		if "UUID16" in self.content:
			self.content['name'] =  AssignedNumbers.getNameByNumber(self.content['UUID16'])			
			self.data = struct.pack('>H',self.content['UUID16'])
			self.content["UUID128"] = b"\x00\x00" + self.data + b"\x00\x00\x10\x00\x80\x00\x00\x80\x5F\x9B\x34\xFB"
		elif "UUID128" in self.content:
			self._correct128()

			if b"\x00\x00\x10\x00\x80\x00\x00\x80\x5f\x9b\x34\xfb" in self.content["UUID128"]:
				self.content["UUID16"] = struct.unpack('>H',self.content["UUID128"][2:4])[0]
				self.data = self.content['UUID16'] if "UUID16" in self.content else self.content['UUID128']
		elif "name" in self.content:
			self.content["UUID16"] = AssignedNumbers.getNumberByName(self.content['name'])
			self.data = struct.pack('>H',self.content['UUID16'])
			self.content["UUID128"] = b"\x00\x00" + self.data + b"\x00\x00\x10\x00\x80\x00\x00\x80\x5F\x9B\x34\xFB"

	def _str128(self,uuid128):
		return uuid128[0:4].hex()+"-"+uuid128[4:6].hex()+"-"+uuid128[6:8].hex()+"-"+uuid128[8:10].hex()+"-"+uuid128[10:16].hex()

	def __str__(self):
		string = "UUID(128bits:"+self._str128(self.content['UUID128'])
		if "UUID16" in self.content:
			string += ", 16bits:"+hex(self.content['UUID16'])
		if "name" in self.content and self.content['name'] is not None:
			string += ", name:"+self.content['name']
		string += " )"
		return string
def isPrintable(theString):
	printableChars = bytes(string.printable, 'ascii') + b"\x00"
	return all(i in printableChars for i in theString)
def isHexadecimal(theString):
	newString = theString[2:] if theString[0:2] == "0x" else theString
	return all(i in "0123456789abcdef" for i in newString.lower())
