top = "TEND\tPROTOCOL\tDPORT\tSIP\tPASS\tclusterCenter\tthreatLevel\n"
TEND = "30"
PROTOCOL = "UDP"
DPORT = "0"
baseSIP = "100.200.300."
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
baseDIP = "100.200."
FlowCount = "0" # this isn't useful
ByteCount = "0"
PacketCount = "1"
RByteCount = "0"

with open("1_links.tsv", "w+") as f:
	f.write(top)
	count = 3000
	for j in range(count):
		if (j < 256):
			DIP = baseDIP + "0." + str(j)
		else:
			quotient = int(j/256)
			DIP = baseDIP + str(quotient) + "." + str(j-(256*quotient))
		for i in range(15):
		  TEND = str(i)
		  line = TEND + "\t" + SIPS[0] + "\t" + DIP + "\t" + FlowCount + "\t" + ByteCount + "\t" + PacketCount + "\t" + RByteCount + "\t" + "0\n"
		  f.write(line)
		if (j%4 == 0):
  		for i in range(15,30):
  		  TEND = str(i)
  		  line = TEND + "\t" + SIPS[0] + "\t" + DIP + "\t" + FlowCount + "\t" + ByteCount + "\t" + PacketCount + "\t" + RByteCount + "\t" + "1\n"
  		  f.write(line)
