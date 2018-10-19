import org.junit.Assert;
import org.junit.Test;

public class SpaceSensitiveFirewallTest {
    @Test
    public void testConstructor() {
        SpaceSensitiveFirewall firewall = new SpaceSensitiveFirewall("rules1.csv");
        Assert.assertEquals(firewall.getFilePath(), "rules1.csv");
    }

    @Test
    public void testAcceptPacket() {
        SpaceSensitiveFirewall firewall = new SpaceSensitiveFirewall("rules1.csv");
        // first rule inbound,tcp,80,192.168.1.12
        Assert.assertTrue(firewall.acceptPacket("inbound", "tcp",80,"192.168.1.12"));
        Assert.assertFalse(firewall.acceptPacket("outbound", "tcp",80,"192.168.1.12"));
        Assert.assertFalse(firewall.acceptPacket("inbound", "udp",80,"192.168.1.12"));
        Assert.assertFalse(firewall.acceptPacket("inbound", "tcp",81,"192.168.1.12"));
        Assert.assertFalse(firewall.acceptPacket("inbound", "tcp",80,"192.168.1.13"));

        // second rule outbound,tcp,10000-20000,192.168.10.11
        Assert.assertTrue(firewall.acceptPacket("outbound", "tcp",15000,"192.168.10.11"));
        Assert.assertTrue(firewall.acceptPacket("outbound", "tcp",10000,"192.168.10.11"));
        Assert.assertTrue(firewall.acceptPacket("outbound", "tcp",20000,"192.168.10.11"));
        Assert.assertFalse(firewall.acceptPacket("inbound", "tcp",15000,"192.168.10.11"));
        Assert.assertFalse(firewall.acceptPacket("outbound", "udp",15000,"192.168.10.11"));
        Assert.assertFalse(firewall.acceptPacket("outbound", "tcp",15000,"192.168.10.12"));

        // third rule inbound,udp,53,192.168.1.1-192.168.2.5
        Assert.assertTrue(firewall.acceptPacket("inbound" ,"udp",53,"192.168.1.255"));
        Assert.assertTrue(firewall.acceptPacket("inbound" ,"udp",53,"192.168.1.1"));
        Assert.assertTrue(firewall.acceptPacket("inbound" ,"udp",53,"192.168.2.5"));
        Assert.assertTrue(firewall.acceptPacket("inbound" ,"udp",53,"192.168.2.0"));
        Assert.assertFalse(firewall.acceptPacket("outbound" ,"udp",53,"192.168.1.255"));
        Assert.assertFalse(firewall.acceptPacket("inbound" ,"tcp",53,"192.168.1.255"));
        Assert.assertFalse(firewall.acceptPacket("inbound" ,"udp",54,"192.168.1.255"));

        // fourth rule outbound,udp,1000-2000,52.12.48.92
        Assert.assertTrue(firewall.acceptPacket("outbound", "udp",1000,"52.12.48.92"));
        Assert.assertTrue(firewall.acceptPacket("outbound", "udp",2000,"52.12.48.92"));
        Assert.assertTrue(firewall.acceptPacket("outbound", "udp",1500,"52.12.48.92"));
        Assert.assertFalse(firewall.acceptPacket("inbound", "udp",1000,"52.12.48.92"));
        Assert.assertFalse(firewall.acceptPacket("outbound", "tcp",1000,"52.12.48.92"));
        Assert.assertFalse(firewall.acceptPacket("outbound", "udp",80,"52.12.48.92"));
        Assert.assertFalse(firewall.acceptPacket("outbound", "udp",1000,"52.12.48.93"));

    }
}
