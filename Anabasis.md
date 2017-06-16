# On being a type-heavy Scheme programmer in InfoSec

or, **how I learnt to hate everything, & love better type systems.**

---

# tl;dw

how do we use types, HOFs, &c. to model not safety, but rather violence?

- support programming in the small
- whilst linearzing our attack flows
- resulting in _roughly_ the sample code density
- with better understanding

---

![Violence](/Users/stefan.edwards/Code/xenophon-curryon/exploits.png)

_Stefan Edwards_ (@lojikil on {github, twitter, lobste.rs, ...})
https://nvisium.com/about/#StefanEdwards

---
	
![I'm deaf](/Users/stefan.edwards/Code/xenophon-curryon/deaf.jpg)

---

![I'm from Noo Yawk](/Users/stefan.edwards/Code/xenophon-curryon/nooyawk.png)

_Yes, we really tawk liek dis. Wanna fite 'bout it?_

---

# FP: large vs small

- known good: large
    - nVP, quants, &c.
- small?  

---

# Hate everything: a long, cacophonous symphony of _failure_

- adversarial approach (opaque box, "red team")
- find and exploit "chains"
- inform client of what the chain _was_

---

# Tools

- {protocol, application} fuzzers
- {SAST, DAST} scanners
- documentation generators

---

# Tools

- `ToolA | ToolB`
- < 100 SLoC

---

# Tools: Example

- DNS enumeration (subdomain brute force)
- find all publicly-known subdomains
    - www0.somedomain.com
    - www1.somedomain.com
    - test-www.somedomain.com
    - origin-www.somedomain.com
    - ...

---

# Tools: DNS Enumeration

```
for domain in domains:
  print "echo ", domain
  print "echo '; BEGIN {0}' >> dnsreport".format(domain)
  print "dig @{0} {1} >> dnsreport".format(servers[idx], 
  					   domain)
  print "echo '; END {0}' >> dnsreport".format(domain)
  for prefix in prefixes:
    name = "{0}.{1}".format(prefix, domain)
    print "echo ", name
    print "echo '; BEGIN {0}' >> dnsreport".format(name)
    print "dig @{0} {1} >> dnsreport".format(servers[idx], 
    				 	     name)
    print "echo '; END {0}' >> dnsreport".format(name)

    idx += 1

    if idx >= len(servers):
      print "sleep 10"
      idx = 0
```

---

# Tools

```
$ python gen_dig.py prefixes domains > dig_domains.sh
$ sh dig_domains > dig_report.dat
$ dig2sqlite dig_report.dat $CLIENT.db

```

---

# Tools - Problems

- execution path
- needle in the haystack

---

# Hate everything - execution path

_exempli gratia_: the existential threat

`Employee Machine` => `Running Application` => `Notice app prints server name` => `CVS access` => **`2.3 GiB of application source code`**


_Side Note: I also stole the red team manual from the client's desk whilst on site. Mo' scope, mo problems._

---

# Hate Everything - needle in the hay stack

_exempli gratia_: "big data"

- Client name
- Source DNS => IP ranges
- Confirm IP ranges (50+ CIDRs, ~3k IPs)
- Hosts, Services, Applications, Infrastructure, &c. &c. &c.
- **40 GiB** of data

> Client: Hey, can you give us a listing of every application found?
> Me: of course!
> _back to bash & grepping through data files & tool output_


---

# Hate Everything

- untennable 
- poorly understood
- fragile
- decentralized
- broken


_kinda like all those security controls I tell clients to replace with models, FP, & types..._

---

# Hate Everything

```
grep -i etag lovetz.txt | grep -v firefox | 
sed -e 's/\[\!\] ETag in response: //' 
-e 's/ for /,/' -e 's/http:\/\///' 
-e 's/https:\/\///' -e 's/\//,\//' -e 's/"//g'
```

---

# and love functional programming & types

1. use defined processes & standards
1. not far from what we already do
1. clean, well-typed information, backed by the tools
1. well-understood chains
1. with modeling of state

---

# and love functional programming & types

1. (NIST SP 800-115, NIST SP 800-61, OWASP Top 10 2013, Common Vulnerability enumerations, &c)
1. `foldDNS |> scanNetwork |> filterWebServices |> scanCSRF`
1. `val foldDNS : string -> string list -> string option list`
1. `currentDNSEntries |> knownWeb |> invalidCSRF`
1. `...`

---

# DNS Enumeration -- Fixed

```
case class DNSCNameRecord(ttl: Int, 
tag: String, 
value: String, 
address: IPAddress) extends DNSRecord;

case class DNSARecord(ttl: Int, 
tag: String, 
value: String, 
address: IPAddress) extends DNSRecord;

// generate FQDNs from word list
def foldNames(baseDomain: String ...): List[String] = ...

// various query engines...
def queryDig(domain: String, 
	type: DNSRecordType): Option[Array[DNSRecord]]
def queryInternal(dom: String, 
	type: DNSRecordType): Option[Array[DNSRecord]]

// . . .
```

---

# Attacks == Models mod harm

- Attack: `foldDNS("somedomain.com", domainPrefixs) andThen lookupDomains`
- 

---

# Web demos

chained:
- web service
- self-XSS
- CSRF
- HTTPOnly cookie

---

# Future Directions 

- modeling architecture
- nVisium Platform (nvp)

---

# Future Directions

Architecture 

- no need to have ARD & code separate
- ARD <=> Code (AWS, VMs/Hypervisors, &c.)
- Typed comms: front-end talks to backend via secure chanel? `TLSDBConnection (frontend-host some-host) (backend-host database-host)`
- Security controls modeled as monads + types

---

# Future Directions

nVisium Platform

- we're working on making this a service
- strongly-typed, modeled service, in Scala
- hybrid analysis/expert system for security