import http from "k6/http";
import encoding from "k6/encoding";

export const options = {
    vus: 200,
    duration: "60s",
};

// PKCS#8 EC private key (P-256)
const es256Pem = open("../secrets/es256-private-pkcs8.pem");

function pemToArrayBuffer(pem) {
    const b64 = pem
        .replace(/-----BEGIN[^-]+-----/g, "")
        .replace(/-----END[^-]+-----/g, "")
        .replace(/\s+/g, "");
    return encoding.b64decode(b64, "std");
}

// header/payload = ASCII. 1 byte per char
function asciiToBytes(str) {
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        buf[i] = str.charCodeAt(i) & 0xff;
    }
    return buf;
}

const keyData = pemToArrayBuffer(es256Pem);

// global import for performance
let keyPromise = crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
        name: "ECDSA",
        namedCurve: "P-256",
    },
    false,
    ["sign"],
);

async function genJwt() {
    const key = await keyPromise;

    const header = encoding.b64encode(
        JSON.stringify({ alg: "ES256", typ: "JWT" }),
        "rawurl",
    );

    const payload = encoding.b64encode(
        JSON.stringify({
            sub: Math.random().toString(36).substring(2),
            iat: Math.floor(Date.now() / 1000),
            rnd: Math.random().toString(36).substring(2),
        }),
        "rawurl",
    );

    const signingInput = `${header}.${payload}`;
    const signingInputBytes = asciiToBytes(signingInput);

    // ECDSA-SHA256
    const sigBuf = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        signingInputBytes,
    );

    const signature = encoding.b64encode(sigBuf, "rawurl");

    return `${signingInput}.${signature}`;
}

export default async function () {
    const jwt = await genJwt();
    http.get("http://localhost:8080/api/ping", {
        headers: { Authorization: `Bearer ${jwt}` },
    });
}
