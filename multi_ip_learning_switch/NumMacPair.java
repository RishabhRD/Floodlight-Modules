package net.floodlightcontroller.iphandler;

import org.projectfloodlight.openflow.types.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NumMacPair implements Comparable<NumMacPair>{
	private MacAddress mac;
	private int numDevices;
	protected static Logger log = LoggerFactory.getLogger(IPHandler.class);
	public NumMacPair(MacAddress mac,int numDevices) {
		this.mac = mac;
		this.numDevices = numDevices;
	}
	public void setMac(MacAddress mac) {
		this.mac = mac;
	}
	public void setDevices(int numDevices) {
		this.numDevices = numDevices;
	}
	public void increment() {
		numDevices++;
	}
	public void decrement() {
		numDevices--;
	}
	public MacAddress getMac() {
		return mac;
	}
	public int getNumberOfDevices() {
		return numDevices;
	}
	@Override
	public int compareTo(NumMacPair o) {
		// TODO Auto-generated method stub
		if(numDevices>o.numDevices) return 1;
		else if (numDevices<o.numDevices) return -1;
		return 0;
	}
	@Override
	public boolean equals(Object o) {
		NumMacPair tmp = (NumMacPair) o;
		if(tmp.getMac().equals(mac)) {
			log.info("MATCH");
			return true;
		}
		log.info("MISS");
		return false;
	}
	
}
