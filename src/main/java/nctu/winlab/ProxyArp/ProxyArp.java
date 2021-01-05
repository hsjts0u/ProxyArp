/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.ProxyArp;

import com.google.common.collect.ImmutableSet;
import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;

/**
  *import
**/

import com.google.common.collect.Lists;
import java.util.HashMap;
import java.util.Optional;
import java.util.List;
import java.nio.ByteBuffer;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onlab.packet.BasePacket;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.ARP;
import org.onlab.packet.MacAddress;
import org.onlab.packet.Ip4Address;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.ConnectPoint;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class ProxyArp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;

    private ProxyArpProcessor processor = new ProxyArpProcessor();

    private HashMap<Ip4Address, MacAddress> IP_MAC = new HashMap<Ip4Address, MacAddress>();

    private HashMap<Ip4Address, ConnectPoint> IP_cp = new HashMap<Ip4Address, ConnectPoint>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nctu.winlab.ProxyArp");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        controllerRequests();
        log.info("Started", appId.id());
    }

    @Deactivate
    protected void deactivate() {
        controllerWithdraws();
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    private void controllerRequests() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void controllerWithdraws() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private class ProxyArpProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if(context.isHandled()) return;

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            ARP arpPkt = (ARP) ethPkt.getPayload();
            short opCode = arpPkt.getOpCode();
            Ip4Address srcIP = Ip4Address.valueOf(arpPkt.getSenderProtocolAddress());
            Ip4Address dstIP = Ip4Address.valueOf(arpPkt.getTargetProtocolAddress());
            MacAddress srcMAC = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());

            if(!IP_MAC.containsKey(srcIP)) {
                IP_MAC.put(srcIP, srcMAC);
            }

            if(!IP_cp.containsKey(srcIP)) {
                ConnectPoint cp = new ConnectPoint(pkt.receivedFrom().deviceId(),
                                                   pkt.receivedFrom().port());
                IP_cp.put(srcIP, cp);
            }

            if(opCode == ARP.OP_REPLY) {
                log.info("RECV REPLY. Requested MAC = {}", IP_MAC.get(srcIP));
                ConnectPoint cp = IP_cp.get(dstIP);
                ByteBuffer bpacket = ByteBuffer.wrap(ethPkt.serialize());
                OutboundPacket outpacket = new DefaultOutboundPacket(cp.deviceId(),
                                                                     DefaultTrafficTreatment.builder().setOutput(cp.port()).build(),
                                                                     bpacket);
                packetService.emit(outpacket);
            }

            if(opCode == ARP.OP_REQUEST) {
                if(!IP_MAC.containsKey(dstIP)) {
                    log.info("TABLE MISS. Send request to edge ports");
                    /*TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
                    Optional<TrafficTreatment> treatment = Optional.empty();
                    ByteBuffer bpacket = ByteBuffer.wrap(ethPkt.serialize());
                    edgePortService.emitPacket(bpacket, treatment);*/
                    ByteBuffer bpacket = ByteBuffer.wrap(ethPkt.serialize());
                    List<ConnectPoint> edgePoints = Lists.newArrayList(edgePortService.getEdgePoints());
                    for(ConnectPoint point : edgePoints) {
                        OutboundPacket outpacket = new DefaultOutboundPacket(point.deviceId(),
                                                                             DefaultTrafficTreatment.builder().setOutput(point.port()).build(),
                                                                             bpacket);
                        packetService.emit(outpacket);
                    }
                } else {
                    log.info("TABLE HIT. Requested MAC = {}", IP_MAC.get(dstIP));
                    ConnectPoint cp = IP_cp.get(srcIP);
                    Ethernet reply = ARP.buildArpReply(dstIP, IP_MAC.get(dstIP), ethPkt);
                    ByteBuffer bpacket = ByteBuffer.wrap(reply.serialize());
                    OutboundPacket outpacket = new DefaultOutboundPacket(cp.deviceId(),
                                                                         DefaultTrafficTreatment.builder().setOutput(cp.port()).build(),
                                                                         bpacket);
                    packetService.emit(outpacket);
                }
            }
        }
    }
}
