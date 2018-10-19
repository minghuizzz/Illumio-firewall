import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class SpaceSensitiveFirewall extends Firewall {
    private String filePath;

    public String getFilePath() {
        return filePath;
    }

    // time complexity: O(1), space complexity: O(1)
    public SpaceSensitiveFirewall(String filePath) {
        this.filePath = filePath;
    }


    // time complexity: O(n), space complexity: O(1)
    // where n is the number of rules in csv file
    @Override
    public boolean acceptPacket(String direction, String protocol, int port, String ip) {
        // read csv file once for each operation
        BufferedReader bufferedReader = null;
        String line = "";
        try {
            bufferedReader = new BufferedReader(new FileReader(filePath));
            while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);

                // use comma as separator
                String[] rule = line.split(",");

                if (rule[0].equals(direction) && rule[1].equals(protocol)
                        && super.checkPort(port, rule[2]) && super.checkIP(ip, rule[3])) {
                    return true;
                }
            }
            return false;

        } catch (Exception e) {
            return false;
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
}
