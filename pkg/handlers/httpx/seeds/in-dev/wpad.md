---
title: WPAD
description: Returns a WPAD config file (Javascript).
weight: 1000 
pattern: /wpad\.dat
is_final: true
data:
  headers:
    "Content-Type": text/javascript
  body: |
    function FindProxyForURL(url, host) {
      if ((host == "localhost") || shExpMatch(host, "localhost.*") || (host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT";
      if (dnsDomainIs(host, "{{ .ProxySrvRegex }}") || shExpMatch(host, "(*.{{ .ProxySrvRegex }}|{{ .ProxySrvRegex }})")) return "DIRECT";
      return 'PROXY {{ .ProxySrv }}:3128; PROXY {{ .ProxySrv }}:3141; DIRECT';
    }
---


WPAD Proxy. Not really useful at the moment. Should be more useful in the future

