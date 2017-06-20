import java.net.{InetAddress, Socket, ConnectException, URLEncoder, URLDecoder}
import java.io.{BufferedReader, InputStreamReader}
import java.util.regex.{Matcher, Pattern}
import scala.util.control.Breaks._
import scala.collection.mutable.ListBuffer

def $$[A, B](x: A, f: A => B): B = f(x)
def manOf[T: Manifest](t: T): Manifest[T] = manifest[T]

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
case class IPv4(val ip: String) extends IPAddress
case class IPv6(val ip: String) extends IPAddress

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

/*
 * Simple DNS record holder; holds basic
 * info you would get out of a DNS query,
 * such as time to live (TTL), but also
 * include a "tag," which we can modify
 * and tag with data as needed. This will
 * allow us to tag sources, or the like.
 */
sealed trait DNSRecord {
    val ttl : Int;
    var tag : String;
    val value : String;
    val address : IPAddress;
}
case class DNSSOARecord(val ttl: Int, var tag: String, val value: String, val address: IPAddress) extends DNSRecord;
case class DNSMXRecord(val ttl: Int, var tag: String, val value: String, val address: IPAddress) extends DNSRecord;
case class DNSCNameRecord(val ttl: Int, var tag: String, val value: String, val address: IPAddress) extends DNSRecord;
case class DNSARecord(val ttl: Int, var tag: String, val value: String, val address: IPAddress) extends DNSRecord;
case class DNSAAAARecord(val ttl: Int, var tag: String, val value: String, val address: IPAddress) extends DNSRecord;
case class DNSTXTRecord(val ttl: Int, var tag: String, val value: String, val address: IPAddress) extends DNSRecord;

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
def foldNames(baseDN: String, subDomains: Array[String]): Array[String] = subDomains map (_ + "." + baseDN) 

/* simple helper methods for creating DNSRecords */
def makeCName(ttl: Int = -1, tag: String = "")(value: InetAddress): DNSCNameRecord = {
    // actually should create A name records...
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

def lookupDomainsInternal(domains: Array[String]) = domains.flatMap(x => queryInternal(x, DNSA)).flatten

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

class Location(val ip: IPAddress, var dns: Option[DNSRecord], var tag: String = "")

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

class Service(val location: Location, val port: Int, val protocol: IPProto, var tag: String = "")

def makeNamedService(host: String, port: Int, address: Option[IPAddress] = None, proto: IPProto = ProtocolTCP, tag: String = ""): Option[Service] = {
    address match {
        case None => queryInternal(host, DNSA) match {
                case Some(dnsrec) => {
                    val rec = dnsrec(0)
                    val loc = new Location(rec.address, Some(rec))
                    Some(new Service(loc, port, proto, tag))
                }
                case None => None
            }
        case Some(ipaddr) => {
            val rec = new DNSCNameRecord(-1, "", host, ipaddr)
            val loc = new Location(ipaddr, Some(rec))
            Some(new Service(loc, port, proto, tag))
        }
    }
}

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

/* Let's talk about the world wide web (interwebbernetz).
 * HTTP itself is actually a fairly simple protocol to
 * model; interactions with servers are fairly straight
 * forward to create & read, and a simple client
 * isn't more than say an hour or two's worth of work.
 *
 * So let's start!
 * 
 * we need:
 * - 'application/x-www-form-urlencoded', which we can reuse
 *   for both query strings & form bodies.
 * - 'text/plain', which we'll use for text uploads
 * - support for cookies
 * - support for headers (Basically maps)
 * - support for various verbs (e.g. GET, POST, ...)
 * - and parsing responses of the same.
 * 
 * now you may be asking "Loji, why write your own?"
 * that's a great question! The reason is that we want
 * to be able to support other, HTTP-like protocols,
 * beyond what, say, Scalaj supports. This is perfect
 * for fuzzing, as well as supporting other protocols
 * quickly and easily.
 */

class Cookie(val name: String = "",
    val value: String = "",
    val expiry: Option[String] = None,
    val path: Option[String] = None,
    val domain: Option[String] = None,
    val httpOnly: Boolean = false,
    val secure: Boolean = false)
    /* not going to support the more
     * modern cookie flags, although
     * adding support wouldn't be
     * overly difficult.
     */

def deflateRequestCookies(cookies: Array[Cookie]): String = {
    //println("deflateRequestCookies: " +  cookies)
    "Cookie: " + cookies.map((x: Cookie) => URLEncoder.encode(x.name, "UTF-8") + "=" + URLEncoder.encode(x.value, "UTF-8")).mkString(";")
}

def deflateResponseCookie(cookie: Cookie): String = {
    val expiry = cookie.expiry match {
        case Some(value) => ";expires=" + value
        case None => ""
    }
    val domain = cookie.domain match {
        case Some(value) => ";domain=" + value
        case None => ""
    }
    val path = cookie.path match {
        case Some(value) => ";path=" + value
        case None => ""
    }
    val httponly = cookie.httpOnly match {
        case true => ";httponly"
        case false => ""
    }
    val secure = cookie.secure match {
        case true => ";secure"
        case false => ""
    }
    "Set-cookie " + URLEncoder.encode(cookie.name, "UTF-8") + "=" + URLEncoder.encode(cookie.value, "UTF-8") + expiry + domain + path + secure + httponly
}

def deflateResponseCookies(cookies: Array[Cookie]): String = {
    cookies.map(deflateResponseCookie).mkString("\r\n")
}

def inflateRequestCookies(rawCookies: String): Option[Array[Cookie]] = {
    None
}

def inflateResponseCookie(rawCookie: String): Option[Cookie] = {

    //println("here in inflateResponseCookie?" + rawCookie)

    if(!rawCookie.toLowerCase().startsWith("set-cookie:")) {
        None
    } else {
        val nameStart = rawCookie.indexOf(':')
        val nameEnd = rawCookie.indexOf('=')
        val name = rawCookie.slice(nameStart + 1, nameEnd).trim()
        val valueEnd = rawCookie.indexOf(';', nameEnd + 1)
        val value = valueEnd match {
            case -1 => rawCookie.slice(nameEnd + 1, rawCookie.length)
            case _ =>  rawCookie.slice(nameEnd + 1, valueEnd)
        }
        // something something other cookie values left as an 
        // exercise to the reader XD
        Some(new Cookie(name, value))
    }
}

def inflateResponseCookies(rawCookies: String): Option[Array[Cookie]] = {
    Some(rawCookies.split("\r\n").flatMap(inflateResponseCookie))
}

/* a simple improvement to these 
 * would be to make a MimeContainer
 * trait, and then add specific 
 * implementations thereof. That way,
 * when reifying/deifying HTTPRequests
 * and HTTPResponses you can easily
 * have multiple types of data.
 * for now, it's a bit more manual.
 */

class HTTPRequest(val host: Service,
                  val method: String,
                  val descriptor: String,
                  val headers: Option[Map[String, String]],
                  val qs: Option[Map[String, String]] = None,
                  val cookies: Option[Array[Cookie]] = None,
                  val data : Option[Map[String, String]] = None,
                  val httpver: String = "HTTP/1.1")

// probably should consider adding a 
// service member to this as well.
class HTTPResponse(val statusline: String,
                   val statuscode: Int,
                   val statusmsg: String,
                   val httpver: String,
                   val headers: Map[String, String],
                   val cookies: Option[Array[Cookie]],
                   val body: String)

/* now we have two helper functions to process
 * query strings & application/x-www-form-urlencoded
 * too. Technically "x-www..." would have %20 for 
 * +, but it works "ok" for simple testing.
 */
def quoteqs(data: Map[String, String]): String = {
    val result = new ListBuffer[String]()
    for( (k, v) <- data) {
        result += URLEncoder.encode(k, "UTF-8") + "=" + URLEncoder.encode(v, "UTF-8")
    }

    result.mkString("&")
}

def parseqs(qs: String): Map[String, String] = {
    val items = qs.split("&")
    val result = new ListBuffer[(String, String)] 
    for( item <- items) {
        val tmp = item.split("=")
        result += ((URLDecoder.decode(tmp(0), "UTF-8"), URLDecoder.decode(tmp(1), "UTF-8")))
    }
    result.toMap
}

def deflateRequest(req: HTTPRequest): String = {
    val result = new ListBuffer[String]

    var qs: String = "";

    val body = req.data match {
        case Some(body_data) => Some(quoteqs(req.data.get))
        case None => None
    }

    req.qs match {
        case Some(x) => qs = "?" + quoteqs(req.qs.get)
        case None => qs = ""
    }

    result += req.method + " " + req.descriptor + qs + " " + req.httpver

    req.headers match{
        case Some(hdrs) => for((k, v) <- hdrs) {
            result += k + ": " + v
        }
        case None => None
    }

    body match {
        case Some(data) => {
            result += "Content-Length: " + data.length
            result += "Content-Type: application/x-www-urlencoded"
        }
        case None => None
    }

    req.cookies match {
        case Some(jar) => result += deflateRequestCookies(jar)
        case None =>
    }

    result += ""

    body match {
        case Some(data) => result += data
        case None => None
    }

    result += ""

    result.mkString("\r\n")
}

/* this would be a *great* place for 
 * monadic parser combinators, but I
 * am not going to implement that just
 * for this demo (tho I *WAS* tempted)
 */
def inflateResponse(rawResponse: String): HTTPResponse = {
    val parts = rawResponse.split("\r\n\r\n")
    val head = parts(0).split("\r\n")
    val statusLine = head(0)
    val rawHeaders = head.slice(1, head.length)
    val headers = new ListBuffer[(String, String)]()

    val tmpOffset0 = statusLine.indexOf(' ')
    val tmpOffset1 = statusLine.indexOf(' ', tmpOffset0 + 1)

    val httpVer = statusLine.slice(0, tmpOffset0)
    val statusCode = Integer.parseInt(statusLine.slice(tmpOffset0 + 1, tmpOffset1))
    val httpMsg = statusLine.slice(tmpOffset1 + 1, statusLine.length) 
    val cookies = new ListBuffer[Cookie]
    val body = parts.length match {
        case 1 => ""
        case 2 => parts(1)
    }

    for(header <- rawHeaders) {
        val tmp = header.split(": ")
        //println("Response header: " + header)
        //println("tmp(0): " + tmp(0))
        tmp(0) match {
            case "Set-cookie" => inflateResponseCookie(header) match {
                case Some(cookie) => cookies += cookie
                case None => None
            }
            case "Set-Cookie" => inflateResponseCookie(header) match {
                case Some(cookie) => cookies += cookie
                case None => None
            }
            case _ => headers += ((tmp(0), tmp(1)))
        }
    }

    var finalCookies: Option[Array[Cookie]] = None
    if(!cookies.isEmpty) {
        //println("here?")
        finalCookies = Some(cookies.toArray)  
    }
    new HTTPResponse(statusLine, statusCode, httpMsg, httpVer, headers.toMap, finalCookies, body)
}

def inflateRequest(rawRequest: String): HTTPRequest = {
    val parts = rawRequest.split("\r\n\r\n")
    val head = parts(0).split("\r\n")
    val requestLine = head(0)
    val rawHeaders = head.slice(1, head.length)
    val headers = new ListBuffer[(String, String)]()
    val body = parts.length match {
        case 0 => None
        case 1 => None
        case 2 => Some(parseqs(parts(1)))
    }
    val requestParts = requestLine.split(' ')
    val descriptParts = requestParts(1).split('?')
    val qs = descriptParts.length match {
        case 1 => None
        case 2 => Some(parseqs(descriptParts(1)))
    }

    for(header <- rawHeaders) {
        val tmp = header.split(": ")
        headers += ((tmp(0), tmp(1)))
    }

    val finalHeaders = headers.toMap

    val host = if(finalHeaders.contains("Host")) {
        makeNamedService(finalHeaders("Host"), 80)
    } else {
        makeNamedService("example.org", 80)
    }

    new HTTPRequest(host.get, requestParts(0), descriptParts(0),
                    Some(finalHeaders), qs, None, body,
                    requestParts(2))
}

def doHTTP(svc: Service, method: String, descriptor: String, httpver: String = "HTTP/1.1", cookies: Option[Array[Cookie]], qs: Option[Map[String, String]] = None, body: Option[Map[String, String]] = None, clientHeaders: Option[Map[String, String]] = None): Option[HTTPResponse] = {
    val hostName = svc.location.dns match {
        case Some(record) => record.value
        case None => svc.location.ip.ip
    }
    val port = svc.port
    val address = svc.location.ip.ip
    val defaultHeaders = Map("Connection" -> "close",
                             "User-Agent" -> "Mozilla/5.0 (violent scala)",
                             "Host" -> hostName)
    val headers = clientHeaders match {
        case Some(hds) => defaultHeaders ++ hds
        case None => defaultHeaders
    }
    val req = new HTTPRequest(svc, method, descriptor, Some(headers), qs, cookies, body, httpver)
    //println("our request: \n" + deflateRequest(req))
    val result = new ListBuffer[String]()
    try {
        val sock = new Socket(address, port)
        val fdin = new BufferedReader(new InputStreamReader(sock.getInputStream()))
        val fdout = sock.getOutputStream()
        var line : String = ""
        val rawRequest = deflateRequest(req)
        fdout.write(rawRequest.getBytes())
        while(line != null) {
            line = fdin.readLine()
            result += line
        }
        sock.close()
        Some(inflateResponse(result.mkString("\r\n"))) 
    } catch {
        case e: Exception => println(e); None
    }
}

def httpGet(svc: Service, descriptor: String, httpver: String = "HTTP/1.1", cookies: Option[Array[Cookie]] = None, qs: Option[Map[String, String]] = None, body: Option[Map[String, String]] = None, headers: Option[Map[String, String]] = None): Option[HTTPResponse] = {
    doHTTP(svc, "GET", descriptor, httpver, cookies, qs, body, headers)
}

def httpPut(svc: Service, descriptor: String, httpver: String = "HTTP/1.1", cookies: Option[Array[Cookie]] = None, qs: Option[Map[String, String]] = None, body: Option[Map[String, String]] = None, headers: Option[Map[String, String]] = None): Option[HTTPResponse] = {
    doHTTP(svc, "PUT", descriptor, httpver, cookies, qs, body, headers)
}

def httpPost(svc: Service, descriptor: String, httpver: String = "HTTP/1.1", cookies: Option[Array[Cookie]] = None, qs: Option[Map[String, String]] = None, body: Option[Map[String, String]] = None, headers: Option[Map[String, String]] = None): Option[HTTPResponse] = {
    doHTTP(svc, "POST", descriptor, httpver, cookies, qs, body, headers) 
}

def httpDelete(svc: Service, descriptor: String, httpver: String = "HTTP/1.1", cookies: Option[Array[Cookie]] = None, qs: Option[Map[String, String]] = None, body: Option[Map[String, String]] = None, headers: Option[Map[String, String]] = None): Option[HTTPResponse] = {
    doHTTP(svc, "DELETE", descriptor, httpver, cookies, qs, body, headers) 
}

def httpTrace(svc: Service, descriptor: String, httpver: String = "HTTP/1.1", cookies: Option[Array[Cookie]] = None, qs: Option[Map[String, String]] = None, body: Option[Map[String, String]] = None, headers: Option[Map[String, String]] = None): Option[HTTPResponse] = {
    doHTTP(svc, "TRACE", descriptor, httpver, cookies, qs, body, headers) 
}

/* ok, so we have HTTP as a *protocol*
 * all set, but what about the things
 * that utiilze it? We can start to 
 * model things like the *forms* and
 * communication order that applications
 * use atop HTTP
 */

def prettyPrintFormValues(k: String, v: String): String = {
    val safeK = URLEncoder.encode(k, "UTF-8")
    val safeV = URLEncoder.encode(v, "UTF-8") 
    val label = "<label for='" + safeK + "'>" + safeK + "</label>"
    val field = "<input type='text' name='" + safeK + "' value='" + safeV + "'>"
    label + field + "<br>"
}

def inflateFormFromMap(params: Map[String, String]): String = params.map(x => x match { case (k, v) => prettyPrintFormValues(k, v) }).mkString("\n")

def inflateForm(body: String): String = inflateFormFromMap(parseqs(body))

def inflateFormFromPost(req: HTTPRequest): Option[String] = {
    // technically, the same idea should work
    // fine for PUT and other requests, but
    // for now this is enough
    // also, could return more than just the inflated data
    // could also work against GET with query strings
    if(!req.method.equals("POST")) {
        None
    } else {
        req.data match {
            case Some(data) => Some(inflateFormFromMap(data))
            case None => None
        }
    }
}

/* hokay! So we've done some attack-types of activities
 * at the application level (in OSI terms), now can we
 * start to create simple attacks against the actual
 * application *above* layer 7?
 *
 * The simplest is a Spider, of course. We can spider the
 * application easily, and return the types of links
 * we find therein. The below is one half of the spider 
 * process, link discovery. To setup the full process,
 * we would just really need to add a Set to back links,
 * and some method of determining what is a link we've
 * already seen (/pages?pageid=515 being notorious for
 * causing problems with spiders, esp. if the pageid 
 * is actually dynamic in some way)
 */
val linkPattern = Pattern.compile("\\s*(?i)(href|src|action)\\s*=\\s*(\"([^\"]*\")|'[^']*'|([^'\">\\s]+))")

def harvestLinks(body: String): Array[(String, String)] = {
    val matcher = linkPattern.matcher(body)
    val results = new ListBuffer[(String, String)]
    while(matcher.find) {
        // no *real* need to decompose these 
        // into two values, but I like doing
        // so on grounds that in doing so we
        // can see what is being matched,
        // better than just saying "read the
        // friendly regex."
        // matcher.group(0) is both:
        val linkType = matcher.group(1)
        val linkValue = matcher.group(2)
        results += ((linkType, linkValue))
    }
    results.toArray
}
