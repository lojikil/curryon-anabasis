import java.net.{InetAddress, Socket, ConnectException}
import scala.collection.mutable.ListBuffer

/* let's setup some simple models here in Scala.
 * for the most part, I'm assuming the easiest 
 * implementation of much of what I'm talking about.
 * for one, this is meant as a demonstration of the
 * point, rather than a complete implementation.
 * for another, Scala won't really be my target
 * (famous last words), because I've already
 * implemented these in other languages that
 * I'm more likely to use longer term. 
 * However, it could be interesting to see what
 * we're doing here in Scala, esp. because we
 * use Scala so heavily at nVisium.
 */
sealed trait IPAddress {
    /* honestly not the best; could be 
     * broken down several ways, including
     * as integer (easy to check if someting
     * is within a CIDR that way!). However,
     * this works for cheap & dirty code to 
     * support a talk.
     */
    val ip: String
}
case class IPv4(ip: String) extends IPAddress
case class IPv6(ip: String) extends IPAddress

/*
 * represent a subset of the DNS record
 * types we could have as case classes.
 * this allows us to have functions that
 * can only operate on certain types of 
 * DNS records.
 * For example, if we're auditing SPF
 * records for mail servers, we'd only
 * want to operate on TXT records. Thus,
 * even for something as simple as that,
 * good compilers + decent types + thought
 * get us great tools on the cheap.
 */
sealed trait DNSRecordType
case object DNSSOA extends DNSRecordType;
case object DNSMX extends DNSRecordType;
case object DNSCName extends DNSRecordType;
case object DNSA extends DNSRecordType;
case object DNSAAA extends DNSRecordType;
case object DNSTXT extends DNSRecordType;

sealed trait DNSRecord {
    val ttl : Int;
    val tag : String;
    val value : String;
    val address : IPAddress;
}
case class DNSSOARecord(ttl: Int, tag: String, value: String, address: IPAddress) extends DNSRecord;
case class DNSMXRecord(ttl: Int, tag: String, value: String, address: IPAddress) extends DNSRecord;
case class DNSCNameRecord(ttl: Int, tag: String, value: String, address: IPAddress) extends DNSRecord;
case class DNSARecord(ttl: Int, tag: String, value: String, address: IPAddress) extends DNSRecord;
case class DNSAAAARecord(ttl: Int, tag: String, value: String, address: IPAddress) extends DNSRecord;
case class DNSTXTRecord(ttl: Int, tag: String, value: String, address: IPAddress) extends DNSRecord;

/*
 * So the idea here is that we want to
 * generate a list of names that could
 * be valid DNS entries for a target.
 * in "real life" this would probably
 * take a set of baseDomains and generate
 * large lists for all domains.
 * Also, subDomains could be anything
 * Seq-able.
 */
def foldNames(baseDN: String, subDomains: List[String]): List[String] = subDomains map (_ + "." + baseDN) 

/* simple helper methods for creating DNSRecords */
def makeCName(ttl: Int = -1, tag: String = "")(value: InetAddress): DNSCNameRecord = {
    DNSCNameRecord(ttl, tag, value.getHostName, IPv4(value.getHostAddress))
}

/* DNS resolvers: do the actual work of name resolution */

def queryInternal(dom: String, recordType: DNSRecordType = DNSA, tag: String = ""): Option[Array[DNSRecord]] = {
    /* because the internal resolver cannot _really_ tell
     * us records by type, we just ignore that parameter.
     */
    try {
        Some(InetAddress.getAllByName(dom) map makeCName(-1, tag))
    } catch {
        case ex: java.net.UnknownHostException => None 
    }
}

def queryDig(dom: String, recordType: DNSRecordType = DNSA, tag: String = ""): Option[Array[DNSRecord]] = {
    queryInternal(dom, recordType, tag)
}

/* A "location" is something that combines the
 * IP address and a DNS record. Why not one or
 * the other? Because on certain assessments we
 * may only have one or the other, and as well,
 * we may discover them at different times. For
 * example, say we have an IP address of 
 * 192.168.150.7; that host may be running services
 * such as web, FTP, &c. that reveal DNS after the 
 * fact.
 */

class Location(val ip: IPAddress, val dns: DNSRecord)

/* A "service" is then combines a location with
 * a known-bound port.
 *
 * first, of course, we have some house keeping
 * to store _what kind_ of protocol we're 
 * dealing with.
 */

sealed trait IPProto
case object ProtocolTCP extends IPProto
case object ProtocolUDP extends IPProto
case object ProtocolSCTP extends IPProto
case object ProtocolAny extends IPProto

class Service(val location: Location,val port: Int, val protocol: IPProto)

/* Having built up locations, services, &c. now we can build
 * simple scanners. Really, a few options to be had
 * here:
 *
 * - an internal simple scanner (ala connect scanner).
 * - shell out to a "real" scanner.
 * 
 * In either case, we want to store our service accesses as
 * Services, and then process those services for further 
 * exploit.
 */

def scanInternal(locations: Array[Location], protocol: IPProto): Option[Array[Service]] = {
    /* super simple connect scanner, for the "top fast ports"
     * nothing complicated, but also not something you'd want
     * to use if better options are available.
     * of course, this should work on even the
     * most restricted of envs that still 
     * support Scala proper. Even if you stick
     * to Scala, there is so many better ways to
     * write this; however, from a pure "infosec will
     * grasp right away" stance, it's great.
     */

    // interestingly, 23 & 25 were hanging at home.
    val shortPorts = Array(1, 7, 9, 21, 22, 80, 81, 110, 111, 115, 443, 8080, 8088, 8443, 8181, 8081)
    val results = ListBuffer[Service]()
    for(location <- locations) {
        for(curPort <- shortPorts) {
            try {
                println("[!] scanning " + location.ip.ip + " port " + curPort)
                val t = new Socket(location.ip.ip, curPort)
                t.close()
                results += new Service(location, curPort, protocol)
                println("added open port")
            } catch {
                case ce: ConnectException => None  
            }
        }
    }

    // HACK: this entire method could be done
    // much more nicely, but... here we are.
    if(results.isEmpty) {
        None
    } else {
        Some(results.toArray)
    }
}

def scanNmap(locations: Array[Location], protocol: IPProto, nmapOpts: String = ""): Option[Array[Service]] = {
    None
}
