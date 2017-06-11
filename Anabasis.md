# On being a type-heavy Scheme programmer in InfoSec

or, how I learnt to hate everything, & love better type systems.

---

- Intro
- Warnings about your brave speaker
- Hate everything. . . 
	- Current infosec problems
	- Current Aproaches 
- And Love FP/types
- Future directions 

---

# tl;dw

how do we use types, HOFs, &c. to model not safety, but rather violence?

other talks:

- "On Being Eeyore in InfoSec"
- "Make Love! The lojikil way"
- "A Heraclitus Seminar: the top 5 things I want mobile devs to stop doing, via Heraclitus"

---

![Violence](/Users/stefan.edwards/Code/xenophon-curryon/exploits.png)

---

![I'm deaf](/Users/stefan.edwards/Code/xenophon-curryon/deaf.jpg)

---

![I'm from Noo Yawk](/Users/stefan.edwards/Code/xenophon-curryon/nooyawk.png)

_Yes, we really tawk liek dis. Wanna fite 'bout it?_

---

# Hate everything

## a long, cacophonous symphony of _failure_

- adversarial approach (opaque box, "red team")
- find and exploit "chains"
- inform client of what the chain _was_

---

# Hate everything

_exempli gratia_: the existential threat

`Employee Machine` => `Running Application` => `Notice app prints server name` => `CVS access` => **`2.3 GiB of application source code`**


_Side Note: I also stole the red team manual from the client's desk whilst on site. Mo' scope, mo problems._

---

# Hate Everything

Problems:

- Command Line hacks: `python something.py | awk 'BEGIN { FS="..." } {...} > dump && nmap -A -sSUV -vvv -Pn -iL dump ...`
- Tons of data
- `.bash_history` != exploit chain

---

# Hate Everything

_exempli gratia_: "big data"

- Client name
- Source DNS => IP ranges
- Confirm IP ranges (50+ CIDRs, ~3k IPs)
- Hosts, Services, Applications, Infrastructure, &c. &c. &c.

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

# DNS demo

---

# IP demos

---

# Web demos

chained:
- web service
- self-XSS
- CSRF
- HTTPOnly cookie

---

# SMTP demo

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