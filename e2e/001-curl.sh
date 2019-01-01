server() {
	qsslcaudit --pid-file "$PID" --output-xml "$XML"
}

client() {
	curl https://localhost:8443/ 2>&1 || true
}
