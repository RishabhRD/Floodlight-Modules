package net.floodlightcontroller.scale;

import org.projectfloodlight.openflow.types.MacAddress;

public class MacBool {
	private boolean delServer = false;
	private boolean delClient = false;
	private MacAddress mac;
	public MacBool(MacAddress mac,boolean delServer,boolean delClient) {
		this.mac = mac;
		this.delServer = delServer;
		this.delClient = delClient;
	}
	public MacAddress getMac() {
		return mac;
	}
	public boolean serverDeletedTag() {
		return delServer;
	}
	public boolean clietDeletedTag() {
		return delClient;
	}
	public void setMac(MacAddress mac) {
		this.mac = mac;
	}
	public void setServerDelete(boolean done) {
		delServer = done;
	}
	public void setClientDelete(boolean done) {
		delClient = done;
	}
	public int hashCode() {
		return mac.hashCode();
	}
	public boolean equals(Object o) {
		if(o instanceof MacAddress) {
			MacAddress cast = (MacAddress) o;
			return mac.equals(cast);
		}else if(o instanceof MacBool) {
			return mac.equals(((MacBool)o).getMac());
		}
		
		return false;
	}
	
}
