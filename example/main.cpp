#include <iostream>
#include "stdlib.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"
#include <cassert>

#pragma GCC optimize ("O3,unroll-loops")
#pragma GCC target ("avx2")

const int N = 10005;
long long si[N], sb[N], sp[N], di[N], db[N], dp[N];

bool check (long long Ai, long long Ap, long long Bi, long long Bp, long long Bb) {
	assert (Bb >= 0 && Bb <= 32);
	Bb = (1LL << Bb);
	Ai %= Bb;
	if (Bp == 0)
		Bp = Ap;
	if (Ai == Bi && Ap == Bp)
		return true;
	return false;
}

long long tab (long long a) {
	long long b = 0;
	for (int i = 0; i < 32; i++) {
		int j = i / 8;
		int b2 = (7 - i % 8) + j * 8;
		if ((a >> i) & 1) {
			b ^= (1LL << b2);
		}
	}
	return b;
}

int main() {
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("../../input.pcap");
	// will be written to it
	pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);
	freopen ("../../sample.filters.txt", "r", stdin);
	for (int i = 0; i < 10000; i++) {
		std::string s, t, r, z;
		std::cin >> s >> t >> r >> z;
		std::string wef, few, wef2, few2;
		bool f = false;
		for (char c : s) {
			if (c == '/') {
				f = true;
				continue;
			}
			if (f) {
				few += c;
			} else {
				wef += c;
			}
		}
		f = false;
		for (char c : r) {
			if (c == '/') {
				f = true;
				continue;
			}
			if (f) {
				few2 += c;
			} else {
				wef2 += c;
			}
		}
		sb[i] = stoi (few);
		db[i] = stoi (few2);
		sp[i] = stoi (t);
		dp[i] = stoi (z);
		pcpp::IPv4Address pdrt (wef);
		si[i] = pdrt.toInt();
		pcpp::IPv4Address pdrt2 (wef2);
		di[i] = pdrt2.toInt();
		si[i] = tab(si[i]);
		di[i] = tab(di[i]);
	}
	if (!pcapWriter.open())
	{
		std::cerr << "Cannot open output.pcap for writing" << std::endl;
		return 1;
	}

	if (reader == NULL)
	{
		std::cerr << "Cannot determine reader for file type" << std::endl;
		return 1;
	}

	if (!reader->open())
	{
		std::cerr << "Cannot open file for reading" << std::endl;
		return 1;
	}

	pcpp::RawPacket rawPacket;
	while (reader->getNextPacket(rawPacket))
	{
		pcpp::Packet parsedPacket(&rawPacket);

		pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
		if (ethernetLayer == NULL)
		{
			continue;
		}

		pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
		if (ipLayer == NULL)
		{
			continue;
		}

		pcpp::IPv4Address srcIp = ipLayer->getSrcIPv4Address();
		pcpp::IPv4Address dstIp = ipLayer->getDstIPv4Address();

		pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
		if (udpLayer == NULL)
		{
			continue;
		}

		//		std::cout << std::endl
		//			<< "Source TCP port: " << udpLayer->getSrcPort() << std::endl
		//			<< "Destination TCP port: " << udpLayer->getDstPort() << std::endl;
		//		std::cout << srcIp << ' ' << dstIp << '\n';
		long long Si = tab(srcIp.toInt()), Sp = udpLayer->getSrcPort() , Di = tab(dstIp.toInt()), Dp = udpLayer->getDstPort();
		bool f = false;
		for (int i = 0; i < 10000; i++) {
			if (check (Si, Sp, si[i], sp[i], sb[i]) && check (Di, Dp, di[i], dp[i], db[i])) {
//				std::cout << i << std::endl;
				f = true;
				break;
			}
		}
		if (f)
			pcapWriter.writePacket(rawPacket);
	}

	return 0;
}
