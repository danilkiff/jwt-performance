import http from "k6/http";
import encoding from "k6/encoding";

export const options = {
    vus: 200,
    duration: "60s",
};

// PKCS#8 private key for RS256
const rs256Pem = open("../secrets/rs256-private-pkcs8.pem");

function pemToArrayBuffer(pem) {
    const b64 = pem
        .replace(/-----BEGIN[^-]+-----/g, "")
        .replace(/-----END[^-]+-----/g, "")
        .replace(/\s+/g, "");
    return encoding.b64decode(b64, "std");
}

// header/payload у нас строго ASCII → достаточно "1 char -> 1 byte"
function asciiToBytes(str) {
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        buf[i] = str.charCodeAt(i) & 0xff;
    }
    return buf;
}

const keyData = pemToArrayBuffer(rs256Pem);

// можно кэшировать промис, чтобы не импортировать ключ на каждый вызов
let keyPromise = crypto.subtle.importKey(
    "pkcs8",
    keyData,
    {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
    },
    false,
    ["sign"],
);

async function genJwt() {
    const key = await keyPromise;

    const header = encoding.b64encode(
        JSON.stringify({ alg: "RS256", typ: "JWT" }),
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

    const sigBuf = await crypto.subtle.sign(
        { name: "RSASSA-PKCS1-v1_5" },
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
