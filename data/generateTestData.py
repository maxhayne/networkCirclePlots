top = "TEND\tPROTOCOL\tDPORT\tSIP\tPASS\tclusterCenter\tthreatLevel\n"
TEND = "30"
PROTOCOL = "UDP"
DPORT = "0"
baseSIP = "1.0.0."
PASS = "1"
clusterCenter = "0"

SIPS = []

with open("test_1_outliers.tsv", "w+") as f:
	f.write(top)
	numPlots = 400
	for i in range(numPlots):
		SIP = baseSIP + str(i)
		threatLevel = str(numPlots-1-i)
		if i < int(numPlots/2):
		  if i < int(numPlots/4):
		    clusterCenter = str(3)
		  else:
		    clusterCenter = str(2)
		else: 
		  clusterCenter = str(1)
		line = TEND + "\t" + PROTOCOL + "\t" + DPORT + "\t" + SIP + "\t" + PASS + "\t" + clusterCenter + "\t" + threatLevel + "\n"
		f.write(line)

		SIPS.append(SIP)

SIPS.reverse()

top = "TEND\tSIP\tDIP\tFlowCount\tByteCount\tPacketCount\tRByteCount\tRPacketCount\n"
TEND = "15"
baseDIP = "2000.2000."
FlowCount = "0" # this isn't regarded
ByteCount = "0"
PacketCount = "1"
RByteCount = "0"

with open("test_1_links.tsv", "w+") as f:
	f.write(top)
	for i in range(len(SIPS)):
		count = 10 + i

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
