---
title: Project Love
date: 2025-01-30
description: Updates and plans
categories: [xodbox]
tags: [dev log]
---


## Background

I created [xodbox](https://github.com/defektive/xodbox) when I was working on the OCSP and doing bug bounties back in 2017. It allowed me to quickly check for remote interactions and easily modify responses to determine if an application had any vulnerabilities in the way it interacted with remote services. I released it publicly in 2020 when I needed it for work. It was not polished or release ready, just a small script and some deployment boilerplate.

It has been successfully used to capture credentials, exfiltrate databases, inject XSS payloads, and much more.

Initially, I chose to write xodbox in Node.js because modifications would be quick. Simply, change the JS then restart the server.

## Pain points

I've encountered a few issues while using it.

- Not everyone likes to program. This prevented some team members from using it.
- While modifying the JS is easy, it is prone to errors.
- Embedding files was cumbersome.
- Deployment dependencies (docker and a few containers)

## Refactor

Rather than refactoring the JS, I wanted to port it over to Golang. In the process I wanted to add some new features:

- Request reflection with multiple response formats (txt, html, xml, jpg, png, gif).
- Built in Let's Encrypt cert setup (no more docker).
- Support for DNS.
- Add Discord notifications. 