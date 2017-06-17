val host = makeNamedService("r.lojikil.com", 8080)
val target = host.get
httpGet(target, "/")
