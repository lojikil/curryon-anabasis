val target = makeNamedService("localhost", 8085).get
val signupResp = httpPost(target,"/signup", "HTTP/1.1", None, None, Some(Map("user" -> "stefan2", "password" -> "hunter2", "confirmp" -> "hunter2")), Some(Map("Referer" -> "http://r.lojikil.com:8080"))).get
val cookieJar = signupResp.cookies.get
httpPost(target, "/survey", "HTTP/1.1", Some(cookieJar), None, Some(Map("survey_form" -> "this is a test")), Some(Map("Referer" -> "http://r.lojikil.com:8080")))
