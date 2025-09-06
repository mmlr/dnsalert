#!/usr/bin/env python3

import http.server
import re
import socket
import socketserver
import struct
import sys
import threading


FLAG_RESPONSE = 1 << 15
FLAG_AUTHORITATIVE = 1 << 10

OPCODE_QUERY = 0 << 11
OPCODE_IQUERY = 1 << 11
OPCODE_STATUS = 2 << 11
OPCODE_MASK = 0xf << 11

RCODE_NXDOMAIN = 3 << 0

POINTER_BITS = 3 << 6

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
QTYPE_ALL = 255

CLASS_IN = 1
CLASS_CS = 2
CLASS_CH = 3
CLASS_HS = 4
QCLASS_ANY = 255


class Handler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		if self.path != '/metrics':
			self.send_response(404)
			self.end_headers()
			return

		self.send_response(200)
		self.send_header('Content-Type', 'text/plain; version=0.0.4')
		self.end_headers()

		metrics = [
			'# TYPE dns_accepted_count counter',
			f'dns_accepted_count {self.server.accepted}',
			'# TYPE dns_rejected_count counter',
			f'dns_rejected_count {self.server.rejected}',
			'# TYPE dns_malformed_count counter',
			f'dns_malformed_count {self.server.malformed}',
			'# TYPE dns_query_count counter'
		]

		for name, count in self.server.counters.items():
			metrics.append(f'dns_query_count{{name="{name}"}} {count}')

		self.wfile.write('\n'.join(metrics + ['']).encode())


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
	def __init__(self):
		http.server.HTTPServer.__init__(self, ('0.0.0.0', 9855), Handler)
		self.counters = {}
		self.accepted = 0
		self.rejected = 0
		self.malformed = 0

	def increment(self, name=None, accepted=0, rejected=0, malformed=0):
		if name is not None:
			if name not in self.counters:
				self.counters[name] = 0
			self.counters[name] += 1

		self.accepted += accepted
		self.rejected += rejected
		self.malformed += malformed


class Label:
	valid = re.compile(b'[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?')
	invalid = re.compile('[^a-zA-Z0-9-]')

	def __init__(self, data, offset=0, nameOffset=0):
		self.data = data[offset:]
		if self.isPointer:
			self.length = 1
		else:
			self.length = data[offset]
			if self.length > 63:
				raise ValueError('label too long')

		self.data = data[offset:offset + self.length + 1]
		self.offset = offset

		if self.isPointer:
			self.pointer = struct.unpack('>H', self.data[:2])[0]
			self.pointer &= ~(POINTER_BITS << 8)
			if offset != 0:
				if self.pointer > offset:
					raise ValueError('pointer referencing forward')
				if self.pointer >= nameOffset:
					raise ValueError('pointer pointing to itself')
		else:
			if self.length > 0 and not self.valid.fullmatch(self.data[1:]):
				raise ValueError('invalid characters in label')

	def build(self):
		return self.data

	def compare(self, other):
		return self.length == other.length \
			and self.data[1:].lower() == other.data[1:].lower()

	def __str__(self):
		return self.invalid.sub('+', self.data[1:].decode())

	@property
	def isNull(self):
		return self.length == 0

	@property
	def isPointer(self):
		return (self.data[0] & POINTER_BITS) == POINTER_BITS

	@classmethod
	def fromData(cls, data, offset, nameOffset):
		label = Label(data, offset, nameOffset)
		return label, offset + label.length + 1

	@classmethod
	def fromString(cls, string):
		encoded = string.encode()
		return Label(struct.pack('>B', len(encoded)) + encoded)

	@classmethod
	def fromPointer(cls, offset):
		data = struct.pack('>H', offset | (POINTER_BITS << 8))
		return Label(data)


class Name:
	def __init__(self, labels):
		self.labels = labels

	def findSuffix(self, other):
		index = -len(other.labels)
		for one, two in zip(self.labels[index:], other.labels):
			if not one.compare(two):
				return None, 0

		return self.labels[index], \
			sum([label.length + 1 for label in self.labels[:index]])

	def build(self):
		return b''.join([label.build() for label in self.labels])

	def __str__(self):
		return '.'.join(
			[str(label) for label in self.labels if not label.isNull])

	@classmethod
	def fromData(cls, data, offset):
		length = 0
		labels = []
		nameOffset = offset
		hasPointers = False
		while True:
			label, offset = Label.fromData(data, offset, nameOffset)
			if label.isPointer:
				resolved, _, _ = Name.fromData(data, label.pointer)
				labels += resolved.labels
				hasPointers = True
				break

			length += label.length + 1
			if length > 255:
				raise ValueError('name too long')

			labels.append(label)
			if label.isNull:
				break

		return Name(labels), offset, hasPointers

	@classmethod
	def fromStrings(cls, strings):
		return Name([Label.fromString(string) for string in strings + ['']])

	@classmethod
	def fromString(cls, string):
		return cls.fromStrings(string.split('.'))


class ResourceRecord:
	def __init__(self, rrType, rrClass, ttl, rData):
		self.name = None
		self.suffix = struct.pack('>HHLH', rrType, rrClass, ttl, len(rData)) \
			+ rData

	def build(self, name):
		return name.build() + self.suffix


class SOARecord(ResourceRecord):
	def __init__(self, name, ttl, serial, refresh, retry, expire, minTTL):
		nameData = name.build()
		mailboxLabelData = Label.fromString('hostmaster').build()
		rData = nameData + mailboxLabelData + nameData \
			+ struct.pack('>LLLLL', serial, refresh, retry, expire, minTTL)

		ResourceRecord.__init__(self, TYPE_SOA, CLASS_IN, ttl, rData)


class SOAInstance:
	def __init__(self, record, name):
		self.record = record
		self.name = name

	def build(self):
		return self.record.build(self.name)


class Question:
	def __init__(self, data, name, qType, qClass):
		self.data = data
		self.name = name
		self.qType = qType
		self.qClass = qClass

	def build(self):
		if self.data is None:
			self.data = self.name.build() \
				+ struct.pack(self.footerFormat, self.qType, self.qClass)

		return self.data

	@classmethod
	def fromData(cls, data, offset):
		start = offset
		name, offset, hasPointers = Name.fromData(data, offset)
		qType, qClass = struct.unpack(cls.footerFormat,
			data[offset:offset + cls.footerLength])
		offset += cls.footerLength
		return Question(None if hasPointers else data[start:offset], name,
			qType, qClass), offset

	@classmethod
	def staticInit(cls):
		cls.footerFormat = '>HH'
		cls.footerLength = struct.calcsize(cls.footerFormat)


class Message:
	def __init__(self, transactionID, flags, questions, answers, auths, adds):
		self.transactionID = transactionID
		self.flags = flags
		self.questions = questions
		self.answers = answers
		self.auths = auths
		self.adds = adds

	def build(self):
		return struct.pack(self.headerFormat, self.transactionID, self.flags,
				len(self.questions), len(self.answers), len(self.auths),
				len(self.adds)) \
			+ b''.join([record.build() for record
				in self.questions + self.answers + self.auths + self.adds])

	@property
	def opCode(self):
		return self.flags & OPCODE_MASK

	@classmethod
	def fromData(cls, data):
		transactionID, flags, questionCount, answerCount, authCount, \
			additionalCount = struct.unpack(cls.headerFormat,
				data[:cls.headerSize])

		questions = []
		offset = cls.headerSize
		for i in range(questionCount):
			question, offset = Question.fromData(data, offset)
			questions.append(question)

		return Message(transactionID, flags, questions, [], [], [])

	@classmethod
	def staticInit(cls):
		cls.headerFormat = '>HHHHHH'
		cls.headerSize = struct.calcsize(Message.headerFormat)


class Types:
	@classmethod
	def staticInit(cls):
		cls.typeNames = {
			TYPE_A: 'A',
			TYPE_NS: 'NS',
			TYPE_CNAME: 'CNAME',
			TYPE_SOA: 'SOA',
			TYPE_PTR: 'PTR',
			TYPE_MX: 'MX',
			TYPE_TXT: 'TXT',
			TYPE_AAAA: 'AAAA',
			QTYPE_ALL: 'ALL'
		}

		cls.classNames = {
			CLASS_IN: 'IN',
			CLASS_CS: 'CS',
			CLASS_CH: 'CH',
			CLASS_HS: 'HS',
			QCLASS_ANY: 'ANY'
		}

		cls.opCodeNames = {
			OPCODE_QUERY: 'QUERY',
			OPCODE_IQUERY: 'IQUERY',
			OPCODE_STATUS: 'STATUS'
		}

	@classmethod
	def lookupName(cls, value, names):
		name = names.get(value)
		return f'unhandled {value}' if name is None else name

	@classmethod
	def lookupType(cls, value):
		return cls.lookupName(value, cls.typeNames)

	@classmethod
	def lookupClass(cls, value):
		return cls.lookupName(value, cls.classNames)

	@classmethod
	def lookupOpCode(cls, value):
		return cls.lookupName(value, cls.opCodeNames)


if len(sys.argv) < 2:
	print(f'usage: {sys.argv[0]} <nameServer> <allowedDomain>'
		' [<allowedDomain>...]')
	sys.exit(1)

host = '0.0.0.0'
port = 53

for which in (Question, Message, Types):
	which.staticInit()

nameServer = Name.fromString(sys.argv[1])
allowedDomains = [Name.fromString(domain) for domain in sys.argv[2:]]
soaRecord = SOARecord(nameServer, 300, 1, 900, 300, 7200, 300)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host, port))

server = Server()
threading.Thread(target=server.serve_forever, daemon=True).start()

while True:
	try:
		data, remote = sock.recvfrom(4096)
		formattedRemote = f'{remote[0]}:{remote[1]}'

		request = Message.fromData(data)

		if request.opCode != OPCODE_QUERY:
			print(f'non-query: {Types.lookupOpCode(request.opCode)};'
				f' remote: {formattedRemote}')
			server.increment(rejected=1)
			continue

		if not request.questions:
			print(f'empty; remote: {formattedRemote}')
			server.increment(rejected=1)
			continue

		auths = []
		questions = []
		dropped = 0
		offset = Message.headerSize
		for question in request.questions:
			accept = True
			if question.qType not in (TYPE_A, TYPE_AAAA, QTYPE_ALL):
				accept = False

			if question.qClass not in (CLASS_IN, QCLASS_ANY):
				accept = False

			for domain in allowedDomains:
				label, labelOffset = question.name.findSuffix(domain)
				if label is not None:
					break
			else:
				accept = False

			print(f'name: {question.name};'
				f' type: {Types.lookupType(question.qType)};'
				f' class: {Types.lookupClass(question.qClass)};'
				f' remote: {formattedRemote}; accept: {accept}')

			if not accept:
				server.increment(rejected=1)
				dropped += len(question.build())
				continue

			server.increment(str(question.name).lower(), accepted=1)

			pointer = Name([Label.fromPointer(offset + labelOffset)])
			soa = SOAInstance(soaRecord, pointer)
			auths.append(soa)

			offset += len(question.build())
			questions.append(question)

		if not questions:
			continue

		reply = Message(request.transactionID,
			FLAG_RESPONSE | FLAG_AUTHORITATIVE | OPCODE_QUERY | RCODE_NXDOMAIN,
			questions, [], auths, [])

		sock.sendto(reply.build(), remote)

	except Exception as exception:
		server.increment(malformed=1)
		print(f'exception: {exception}; remote: {formattedRemote}')
