function FindProxyForURL(url, host) {
    if ((host == "localhost") || shExpMatch(host, "localhost.*") || (host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT";
    if (dnsDomainIs(host, "ProxySrvRegex") || shExpMatch(host, "(*.ProxySrvRegex|ProxySrvRegex)")) return "DIRECT";
    return 'PROXY ProxySrv:3128; PROXY ProxySrv:3141; DIRECT';
}
