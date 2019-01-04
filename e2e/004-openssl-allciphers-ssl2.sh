server() {
	qsslcaudit --pid-file "$PID" --output-xml "$XML"
}

client() {
	openssl-unsafe s_client -host localhost -port 8443 -cipher ALL -ssl2 < /dev/null || true
}
