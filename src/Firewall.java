public abstract class Firewall {

    public abstract boolean acceptPacket(String direction, String protocol, int port, String ip);

    // check if the input port match the expected ports
    public boolean checkPort(int port, String expectedPorts) {
        if (expectedPorts.contains("-")) {
            String[] ports = expectedPorts.split("-");
            if (port >= Integer.parseInt(ports[0]) && port <= Integer.parseInt(ports[1])) {
                return true;
            } else {
                return false;
            }
        } else {
            if (port == Integer.parseInt(expectedPorts)) {
                return true;
            } else {
                return false;
            }
        }
    }

    // check if the input ip match the expected ips
    public boolean checkIP(String ip, String expectedIPs) {
        if (expectedIPs.contains("-")) {
            String[] ips = expectedIPs.split("-");
            String[] startIP = ips[0].split("\\.");
            String[] endIP = ips[1].split("\\.");
            String[] targetIP = ip.split("\\.");

            for (int i = 0; i < 4; i++) {
                if (Integer.parseInt(targetIP[i]) < Integer.parseInt(startIP[i])
                        || Integer.parseInt(targetIP[i]) > Integer.parseInt(endIP[i])) {
                    return false;
                } else if (Integer.parseInt(targetIP[i]) > Integer.parseInt(startIP[i])
                        || Integer.parseInt(targetIP[i]) < Integer.parseInt(endIP[i])) {
                    return true;
                }
            }
            return true;
        } else {
            return ip.equals(expectedIPs);
        }
    }

}
