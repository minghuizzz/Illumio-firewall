import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class TimeSensitiveFirewall extends Firewall {
    private String filePath;
    public String getFilePath() {
        return filePath;
    }

    private String[][][][] rules; // can be replaced by map if 65535 is thought big for the system

    // time complexity: O(n), space complexity: O(n)
    // where n is the number of rules in csv file
    public TimeSensitiveFirewall(String filePath) {
        this.filePath = filePath;
        this.rules = new String[2][2][65535][1];

        BufferedReader bufferedReader = null;
        String line = "";
        try {
            bufferedReader = new BufferedReader(new FileReader(filePath));
            while ((line = bufferedReader.readLine()) != null) {

                // use comma as separator
                String[] rule = line.split(",");
                int directionIndex = rule[0].equals("inbound") ? 0 : 1;
                int protocolIndex = rule[1].equals("tcp") ? 0 : 1;
                int startPortIndex = 0;
                int endPortIndex = 0;
                if (rule[2].contains("-")) {
                    String[] ports = rule[2].split("-");
                    startPortIndex = Integer.parseInt(ports[0]) - 1;
                    endPortIndex = Integer.parseInt(ports[1]) - 1;
                } else {
                    startPortIndex = Integer.parseInt(rule[2]) - 1;
                    endPortIndex = startPortIndex;
                }
                for (int portIndex = startPortIndex; portIndex <= endPortIndex; portIndex++) {
                    if (this.rules[directionIndex][protocolIndex][portIndex][0] == null) {
                        this.rules[directionIndex][protocolIndex][portIndex][0] = rule[3];
                    } else {
                        this.rules[directionIndex][protocolIndex][portIndex][0] += "," + rule[3];
                    }
                }


            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // time complexity: O(m), space complexity: O(n)
    // where n is the number of rules in csv file
    // m is the number of ip ranges of specif direction, protocol and port
    @Override
    public boolean acceptPacket(String direction, String protocol, int port, String ip) {
        int directionIndex = direction.equals("inbound") ? 0 : 1;
        int protocolIndex = protocol.equals("tcp") ? 0 : 1;
        int portIndex = port - 1;

        if (this.rules[directionIndex][protocolIndex][portIndex][0] == null) {
            return false;
        }

        String[] ipRanges = this.rules[directionIndex][protocolIndex][portIndex][0].split(",");
        for (String ipRange : ipRanges) {
            if (super.checkIP(ip, ipRange)) {
                return true;
            }
        }
        return false;
    }


}
