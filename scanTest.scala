val g = queryInternal("r.lojikil.com").get
val h = new Location(g(0).address, g(0))
scanInternal(Array[Location](h), ProtocolTCP)
