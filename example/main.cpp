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

int main() {
    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("input.pcap");
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
        
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == NULL)
        {
            continue;
        }

        std::cout << std::endl
            << "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
            << "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
            << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl;
    }

    return 0;
}
