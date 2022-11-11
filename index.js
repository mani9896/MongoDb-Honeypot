const net = require('net');
const ref = require('ref')
const fs = require('fs');
const bson = require('bson');
const parseArgs = require('minimist');

var nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: '2019282@iiitdmj.ac.in',
        pass: 'aiuooobbsnpacwci'
    }
});

var args = parseArgs(process.argv);

if(args.h || args.help) {
    console.log("Help:");
    console.log("--address, -a: The ip of the dummy mongodb instance");
    console.log("                Default: 127.0.0.1");
    console.log("--port, -p:    The port of the dummy mongodb instance");
    console.log("                Default: 27016");
    console.log("-l, --listen:  The port to listen on");
    console.log("                Default: 27017");
    console.log("-o, --out:     The file to output logs to");
    console.log("                Default: proxy.log");
    console.log("-h, --help:    Displays this message and returns");
    process.exit()
}

const EXTERNAL_PORT = args.listen || args.l || 27017;
const MONGODB_HOST = args.address || args.a || "mongo"
const MONGODB_PORT = args.port || args.p || 27017;
const LOG_FILE = args.out || args.o || "proxy.log";

//A really hacky logging method.
var oldLog = console.log;
console.log = function(data) {
    data = data.toString().replace(/[^\x00-\x7F]/g, "").trim();
    if(LOG_FILE) {
        fs.appendFileSync(LOG_FILE, "[" + new Date().toISOString() + "] " + data + "\r\n");
    }
    oldLog("[" + new Date().toISOString() + "] " + data)
}

let ipSet = new Set();

function printFromAddress(fromIp, data) {
    console.log("[" + fromIp + " -> S] " + data);
    let ip = fromIp.split(":")[2];
    if (!ipSet.has(ip)) {
        console.log(data);
        var mailOptions = {
            from: '2019282@iiitdmj.ac.in',
            to: 'mananjethwani02@gmail.com',
            subject: 'Alert intrusion Detected!!',
            text: `Received request from ${fromIp} to the server \n the data sent is as follows- ${data}`
        };
    
        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });
        ipSet.add(ip);
    }
}
function printToAddress(fromIp, data) {
    console.log("[S -> " + fromIp + "] " + data);
}

var server = net.createServer(function (socket) {
    var clientId = socket.remoteAddress + ":" + socket.remotePort;
    var tag = "[" + clientId + "] ";
    console.log(clientId + " connected.")
    try {
        socket.on('data', function (msg) {
            console.log('<< From client to proxy ', msg.toString());
            var serviceSocket = new net.Socket();
            console.log(clientId + " -> Server:");
            var packet = parseMessage(msg, clientId);
            if(packet != null && packet instanceof OpQuery) {
                console.log(packet.query.toString());
                var fingerprint = "";
                if(packet.query && packet.query.length > 0 && packet.query[0].client) {
                    fingerprint = packet.query[0].client;
                }
                if(packet.query && packet.query.length > 0) {
                    printFromAddress(clientId, "login", JSON.stringify(packet.query[0]))
                } else {
                    printFromAddress(clientId, JSON.stringify(packet.query[0]))
                }
            }
            try {
                serviceSocket.connect(MONGODB_PORT, MONGODB_HOST, function () {
                    serviceSocket.write(msg);
                });
                serviceSocket.on("data", function (data) {
                    parseMessage(data, clientId);
                    printToAddress(clientId, data);
                    socket.write(data);
                });
                socket.on("close", function () {
                    console.log("error");
                })
            } catch (err) {
                console.log("hello");
            }
        });
    } catch (err) {
        console.log("error");
    }
    socket.on('close', function() {
        console.log(clientId + " disconnected.");
    });
});
server.listen(EXTERNAL_PORT);
console.log("Proxy listening on " + EXTERNAL_PORT + ".");

var offset = 0;
function parseMessage(data, identifier) {
    offset = 0;
    var header = new MsgHeader(data);
    switch(header.opCode) {
        case 2004:
            var packet = new OpQuery(data);
            printFromAddress(identifier, packet.toString());
            return packet;
        case 1:
            var packet = new OpReply(data);
            printFromAddress(identifier, packet.toString());
            return packet;
        default:
            printFromAddress(identifier, "Unimplemented opcode " + header.opCode);
            printFromAddress(identifier, "Raw packet (" + header.opCode + "): \n" + data.toString())
            return null;
    }

}

function OpReply(data) {
    this.flags = readInt32(data);
    this.cursorId = readInt64(data);
    this.startingFrom = readInt32(data);
    this.docCount = readInt32(data);
    var docs = [];
    bson.deserializeStream(data, offset, this.docCount, docs, 0);
    this.documents = docs;
    this.toString = function() {
        var result = "";
        if(this.flags > 0) {
            result += "Flags: " + this.flags + "\n";
        }
        if(this.documents.length > 0) {
            result += "Documents: " + JSON.stringify(this.documents) + "\n";
        }
        return result;
    }
}

function OpQuery(data) {
    this.flags = readInt32(data);
    this.collectionName = readCString(data);
    this.numToSkip = readInt32(data);
    this.numToReturn = readInt32(data);
    var returnCount = this.numToReturn;
    var docs = [];
    bson.deserializeStream(data, offset, 1, docs, this.numToSkip);
    this.query = docs;
    if(offset < data.length) {
        var fields = [];
        bson.deserializeStream(data, offset, 1, fields, this.numToSkip);
        this.returnFieldsSelector = fields
    }
    this.toString = function() {
        var result = "";
        if(this.flags > 0) {
            result += "Flags: " + this.query + "\n";
        }
        if(this.query.length > 0) {
            result += "Query: " + JSON.stringify(this.query) + "\n";
        }
        if(this.returnFieldsSelector) {
            result += "Return Fields: " + JSON.stringify(this.returnFieldsSelector) + "\n";
        }
        return result;
    }
}

function readCString(data) {
    var cstring = ref.readCString(data, offset);
    console.log(cstring);
    offset += Buffer.byteLength(cstring, 'utf8') + 1;
    return cstring;
}

function MsgHeader(data) {
    console.log(data);
    this.messageLength = readInt32(data);
    this.requestID = readInt32(data);
    this.responseTo = readInt32(data);
    this.opCode = readInt32(data);
}

function readInt32(data) {
    try {
        var value = data.readInt32LE(offset);
        offset += 4;
        return value;
    } catch(err) {
        return 
    }
}
function readInt64(data) {
    var value = ref.readInt64LE(data, offset);
    offset += 8;
    return value;
}
