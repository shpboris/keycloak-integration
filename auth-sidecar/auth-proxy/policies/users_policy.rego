package auth
default allow = false
allow = true {
    input.method == "GET"
}
allow = true {
    input.claims.preferred_username == "admin"
}