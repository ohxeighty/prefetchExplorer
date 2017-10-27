#Credit to http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format and https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc for file format info

import argparse
import sys
import struct
import datetime
import binascii
import os

#def usage():
#	args.print_help()

class volume():
	def __init__(self, path, creationTime, serialNumber,directoryStrings):
		self.path = path
		self.creationTime = creationTime
		self.serialNumber = serialNumber
		self.directoryStrings = directoryStrings

class parsedFile():
	def __init__(self, name, size, version, supportingFiles, volumeInfo, runCount, lastExecuted):
		self.name = name
		self.size = size
		self.version = version
		self.supportingFiles = supportingFiles
		self.volumeInfo = volumeInfo
		self.runCount = runCount
		self.lastExecuted = lastExecuted

def error(error="", fatal=0):
	print "[!] Error: " + error
	if fatal:
		sys.exit(1)

def format_output(file):
	output = str(file.name) + "\n" + "Size: " + str(file.size) + "\n" + str(file.version) + "\nRun Count: " + str(file.runCount) + "\nLast Run: " + str(file.lastExecuted) + "\nSupporting Files\n\n"
	for i in file.supportingFiles:
		output+="\t" + str(i) + "\n\n"

	output+="\n===========\nVolume Info\n===========\n"

	for i in file.volumeInfo:
		output+="Path: " + str(i.path) + "\nCreation Time: " + str(i.creationTime) + "\nSerial Number: " + str(i.serialNumber) + "\nDirectory Strings\n\n"
		for i in i.directoryStrings:
			output+="\t" + str(i) + "\n"

	return output

def parse_file(file):
	try:
		f = open(file, "rb")
	except:
		error("Could not open file", 1)

	#Read and determine version
	fVersion = struct.unpack("<I", f.read(4))[0]
	if fVersion == 17:
		version = "Windows XP / 2003"
	elif fVersion == 23:
		version = "Windows Vista / 7"
	elif fVersion == 26:
		version = "Windows 8 / 8.1"
	elif fVersion == 30:
		version = "Windows 10"
	else:
		error("No file version, corrupted or not a prefetch file", 1)

	#File size
	f.seek(12)
	fLength = struct.unpack("<I", f.read(4))[0]

	#File Name
	f.seek(16)
	fName = f.read(60).decode("utf-16")

	# Strips out garbage
	fName = fName.split("\x00")[0]

	#Read file header dependant on version, record offsets as well as last execution time and run counter
	f.seek(84)
	oA = struct.unpack("<I", f.read(4))[0]
	eA = struct.unpack("<I", f.read(4))[0]
	oB = struct.unpack("<I", f.read(4))[0]
	eB = struct.unpack("<I", f.read(4))[0]
	oC = struct.unpack("<I", f.read(4))[0]
	lC = struct.unpack("<I", f.read(4))[0]
	oD = struct.unpack("<I", f.read(4))[0]
	eD = struct.unpack("<I", f.read(4))[0]
	lD = struct.unpack("<I", f.read(4))[0]

	if fVersion == 17:
		f.seek(120)
		#Convert FILETIME to DATETIME
		#Is stored in miliseconds since 1/1/1601
		lastExecution = (struct.unpack("<I", f.read(4))[0]) / 10.
		lastExecution = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=lastExecution)
		f.seek(144)
		runCount = struct.unpack("<I", f.read(4))[0]
	elif fVersion == 23:
		f.seek(128)
		lastExecution = (struct.unpack("<I", f.read(4))[0]) / 10.
		lastExecution = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=lastExecution)
		f.seek(152)
		runCount = struct.unpack("<I", f.read(4))[0]
	elif fVersion == 26:
		f.seek(128)
		lastExecution = (struct.unpack("<I", f.read(4))[0]) / 10.
		lastExecution = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=lastExecution)
		f.seek(208)
		runCount = struct.unpack("<I", f.read(4))[0]
	#Section B is the Trace Chains Array?

	#List of supporting files, Section C
	f.seek(oC)
	temp = f.read(lC).decode("utf-16")

	#Split on null byte
	supportingFiles = temp.split("\x00")

	#Section D Volume Info
	volumeInfo = []
	for i in range(eD):
		f.seek(oD+(i*lD))
		oV = struct.unpack("<I", f.read(4))[0]
		lV = struct.unpack("<I", f.read(4))[0]

		#Volume Creation Time
		creationTime = (struct.unpack("<Q", f.read(8))[0]) / 10.
		creationTime = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=creationTime)

		#Volume Serial Number
		serialNumber = hex(struct.unpack_from("<I", f.read(4))[0]).strip("0x")
		oF = struct.unpack("<I", f.read(4))[0]
		lF = struct.unpack("<I", f.read(4))[0]
		oDS = struct.unpack("<I", f.read(4))[0]
		eDS = struct.unpack("<I", f.read(4))[0]

		#Volume Path
		f.seek(oV+oD+(i*lD))

		#Length to include terminating \x00 for decode ( I think )
		volumePath = f.read(lV * 2).decode("utf-16")

		# Not quite sure what the NTFS file reference is, 6 bytes for an MFT entry index and 2 for a sequence number.

		#Directory Strings
		f.seek(oD + oDS)
		directoryStrings = []
		for i in range(eDS):
			length = struct.unpack_from("<H", f.read(2))[0]
			directoryString = f.read(length*2).decode("utf-16")
			directoryStrings.append(directoryString)

		volumeInfo.append(volume(volumePath,creationTime,serialNumber, directoryStrings))

	return parsedFile(fName, fLength, version, supportingFiles, volumeInfo, runCount, lastExecution)

#main
parser = argparse.ArgumentParser(description="Parses prefetch files.")
parser.add_argument('-o', '--output', help ="output file", required = False, default = None)

selection = parser.add_mutually_exclusive_group(required=True)
selection.add_argument('-f', '--file', help ="parse given file path", required = False, default = None)
selection.add_argument('-d', '--directory', help ="parse all files in specified directory", required = False, default = None)

args = parser.parse_args()

if args.file:
	file = parse_file(args.file)
	write = format_output(file)
	print write

	if args.output:
		try:
			out = open(args.output, "w")
			out.write(write)
		except:
			error("Could not output to file")

elif args.directory:
	try:
		output = ""
		for file in os.listdir(args.directory):
			if file.endswith(".pf"):
				try:
					print args.directory+"\\"+file
					file = parse_file(args.directory+"\\"+file)
					write = format_output(file)
					print write

					output+=write
				except:
					error("Could not parse file, skipping")
		if args.output:
			try:
				out = open(args.output, "w")
				out.write(output)
			except:
				error("Could not output to file")
	except:
		error("Directory does not exist")
