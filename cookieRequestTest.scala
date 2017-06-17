val target = makeNamedService("r.lojikil.com", 8080).get
val jar = Array(new Cookie("foo", "bar"), new Cookie("bar", "baz"))
val req = new HTTPRequest(target, "GET", "/", None, None, Some(jar))
