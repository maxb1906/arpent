package portscan

// wellKnown associe un port TCP à son service habituel, pour l'affichage en
// attendant l'identification réelle par les sondes (internal/probe).
var wellKnown = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp", 135: "msrpc",
	139: "netbios-ssn", 143: "imap", 389: "ldap", 427: "svrloc", 443: "https", 445: "smb",
	465: "smtps", 515: "lpd", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
	636: "ldaps", 873: "rsync", 902: "vmware", 990: "ftps", 993: "imaps", 995: "pop3s",
	1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
	2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3128: "http-proxy",
	3260: "iscsi", 3306: "mysql", 3389: "rdp", 5000: "upnp/http", 5001: "https-alt",
	5060: "sip", 5061: "sips", 5222: "xmpp", 5357: "wsd", 5432: "postgresql", 5555: "adb",
	5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc", 5985: "winrm", 5986: "winrm-tls",
	6379: "redis", 6443: "kubernetes", 7547: "cwmp", 8006: "proxmox", 8008: "http-alt",
	8009: "ajp", 8080: "http-alt", 8081: "http-alt", 8123: "home-assistant", 8291: "winbox",
	8443: "https-alt", 8554: "rtsp", 8728: "mikrotik-api", 8883: "mqtts", 8888: "http-alt",
	9000: "http-alt", 9090: "http-alt", 9100: "jetdirect", 9200: "elasticsearch",
	9443: "https-alt", 10000: "webmin", 11211: "memcached", 27017: "mongodb", 32400: "plex",
	62078: "iphone-sync",
}

// ServiceName renvoie le service habituel d'un port TCP, ou "".
func ServiceName(port int) string { return wellKnown[port] }
