top = "TEND\tPROTOCOL\tDPORT\tSIP\tPASS\tclusterCenter\tthreatLevel\n"
TEND = "30"
PROTOCOL = "UDP"
DPORT = "0"
baseSIP = "1.0.0."
PASS = "1"
clusterCenter = "0"

SIPS = []

with open("25_outliers.tsv", "w+") as f:
	f.write(top)
	for i in range(25):
		SIP = baseSIP + str(i)
		threatLevel = str(24-i)
		line = TEND + "\t" + PROTOCOL + "\t" + DPORT + "\t" + SIP + "\t" + PASS + "\t" + clusterCenter + "\t" + threatLevel + "\n"
		f.write(line)

		SIPS.append(SIP)

SIPS.reverse()

top = "TEND\tSIP\tDIP\tFlowCount\tByteCount\tPacketCount\tRByteCount\tRPacketCount\n"
TEND = "15"
baseDIP = "10.0."
FlowCount = "0" # this isn't regarded
ByteCount = "0"
PacketCount = "1"
RByteCount = "0"

with open("25_InOut.tsv", "w+") as f:
	f.write(top)
	for i in range(len(SIPS)):
		count = 99 + (100*i)

		for j in range(count):
			if (j < 256):
				DIP = baseDIP + "0." + str(j)
			else:
				quotient = int(j/256)
				DIP = baseDIP + str(quotient) + "." + str(j-(256*quotient))
			for k in range(30):
			  if ((j)%10):
			    line = str(j+1) + "\t" + SIPS[i] + "\t" + DIP + "\t" + FlowCount + "\t" + ByteCount + "\t" + PacketCount + "\t" + RByteCount + "\t" + "1\n"
			  else:
			    line = str(j+1) + "\t" + SIPS[i] + "\t" + DIP + "\t" + FlowCount + "\t" + ByteCount + "\t" + PacketCount + "\t" + RByteCount + "\t" + "0\n"
			  f.write(line)
