val g = makeNamedService("r.lojikil.com", 8080)
val svc = g.get
val req = new HTTPRequest(svc, "POST", "/foo", None, Some(Map("q" -> "bar")), Some(Array(new Cookie("test", "cookie"))), Some(Map("user" -> "stefan", "password" -> "hunter2")))
deflateRequest(req)
