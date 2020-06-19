top = "TEND\tPROTOCOL\tDPORT\tSIP\tPASS\tclusterCenter\tthreatLevel\n"
TEND = "30"
PROTOCOL = "UDP"
DPORT = "0"
baseSIP = "1.0.0."
PASS = "1"
clusterCenter = "0"

SIPS = []

with open("1_outliers.tsv", "w+") as f:
	f.write(top)
	SIP = baseSIP + str(1)
	threatLevel = str(1)
	line = TEND + "\t" + PROTOCOL + "\t" + DPORT + "\t" + SIP + "\t" + PASS + "\t" + clusterCenter + "\t" + threatLevel + "\n"
	f.write(line)
	SIPS.append(SIP)

top = "TEND\tSIP\tDIP\tFlowCount\tByteCount\tPacketCount\tRByteCount\tRPacketCount\n"
TEND = ["15","30"]
baseDIP = "10.0."
FlowCount = "0" # this isn't regarded
ByteCount = "0"
PacketCount = "1"
RByteCount = "0"

with open("1_InOut.tsv", "w+") as f:
	f.write(top)
	count = 200 + int((0))
	for j in range(count):
		if (j < 256):
			DIP = baseDIP + "0." + str(j)
		else:
			quotient = int(j/256)
			DIP = baseDIP + str(quotient) + "." + str(j-(256*quotient))
		line = TEND[0] + "\t" + SIPS[0] + "\t" + DIP + "\t" + FlowCount + "\t" + ByteCount + "\t" + PacketCount + "\t" + RByteCount + "\t" + "0\n"
		f.write(line)
		line = TEND[1] + "\t" + SIPS[0] + "\t" + DIP + "\t" + FlowCount + "\t" + ByteCount + "\t" + PacketCount + "\t" + RByteCount + "\t" + "1\n"
		#f.write(line)
		# for i in range(10):
		#   f.write(line)
		if (j%5):
		  f.write(line)
		# for i in range(20):
		#  f.write(line)
