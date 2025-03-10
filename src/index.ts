import express, { Request, Response } from 'express';
import * as fs from 'fs';
import { Readable } from "stream";
import * as zlib from "zlib";

const app = express();
const cors = require("cors");
const { pipeline } = require('node:stream');
const easyxml = require('easyxml');
const port = process.env.PORT || 3000;

app.use(cors());

var serializer = new easyxml({
    singularize: true,
    rootElement: 'response',
    dateFormat: 'ISO',
    manifest: true
});


app.get('/get', (req: Request, res: Response) => {
    res.send('Success');
});

app.get("/get-json", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "application/json");
    res.json({ "express": "get-json success" })
})

app.get("/get-html", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/html");
    res.sendFile(__dirname + '/public/html/hello.html');
})

app.get("/get-xml", (req: Request, res: Response) => {
    res.header('Content-Type', 'text/xml');
    var obj = {
        items: [{
            name: 'one',
            _id: 1
        }, {
            name: 'two',
            _id: 2
        }, {
            name: 'three',
            _id: 3
        }],
        blah: 'http://www.google.com',
        when: new Date(),
        boolz: true,
        nullz: null
    };
    var xml = serializer.render(obj);
    res.send(xml);
})

app.get("/get-png", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "image/png");
    res.sendFile(__dirname + '/public/image/penguin.png');
})

app.get("/get-svg", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "image/svg+xml");
    res.sendFile(__dirname + '/public/image/atom.svg');
})

app.get("/get-movie", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "video/mp4");
    res.sendFile(__dirname + "/public/video/test.mp4");
})

app.get("/get-gif", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "image/gif");
    res.sendFile(__dirname + "/public/image/animate.gif");
})

app.get("/get-zip", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "application/zip");
    res.sendFile(__dirname + "/public/file/font.zip");
})

app.get("/get-gzip", (request: Request, response: Response) => {
    const raw = Readable.from([Buffer.from("Hello, world!")]);
    response.setHeader('Vary', 'Accept-Encoding');
    let acceptEncoding = request.headers['accept-encoding'] as string;
    if (!acceptEncoding) {
        acceptEncoding = '';
    }
    const onError = (err: any) => {
        if (err) {
            response.end();
            console.error('An error occurred:', err);
        }
    };
    if (/\bdeflate\b/.test(acceptEncoding)) {
        response.writeHead(200, { 'Content-Encoding': 'deflate' });
        pipeline(raw, zlib.createDeflate(), response, onError);
    } else if (/\bgzip\b/.test(acceptEncoding)) {
        response.writeHead(200, { 'Content-Encoding': 'gzip' });
        pipeline(raw, zlib.createGzip(), response, onError);
    } else if (/\bbr\b/.test(acceptEncoding)) {
        response.writeHead(200, { 'Content-Encoding': 'br' });
        pipeline(raw, zlib.createBrotliCompress(), response, onError);
    } else {
        response.writeHead(200, {});
        pipeline(raw, response, onError);
    }
});

///AuthType
app.get("/auth-type", (request: Request, response: Response) => {
    const authheader = request.headers.authorization;
    console.log(request.headers);

    if (!authheader) {
        let err = new Error('You are not authenticated!');
        response.setHeader('WWW-Authenticate', 'Basic');
        response.statusCode = 401
        response.send(err)
        return
    }

    const auth = Buffer.from(authheader.split(' ')[1],
        'base64').toString().split(':');
    const user = auth[0];
    const pass = auth[1];
    console.log(`user ${user}`);
    console.log(`password ${pass}`);
    response.send("success")
});

/// encryption
// 1. aes encryption
// 2. rsa encryption

/// base64

/// hash

/// certificate

/// different auth mode

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});