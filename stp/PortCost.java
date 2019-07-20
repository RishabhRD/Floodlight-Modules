package net.floodlightcontroller.stp;

import org.projectfloodlight.openflow.types.OFPort;

public class PortCost {
	public OFPort port= null;
	public int cost = -1;
	public PortCost() {
		port = null;
		cost  = -1;
	}
	public PortCost(OFPort port ,int cost) {
		this.port = port;
		this.cost = cost;
	}
}
