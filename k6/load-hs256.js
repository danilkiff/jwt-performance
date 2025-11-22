import http from "k6/http";
import crypto from "k6/crypto";
import encoding from "k6/encoding";

export const options = {
    vus: 1000,
    duration: "60s",
};

const secret = open("../secrets/hs256-secret.txt").trim();

function genJwt() {
    // base64url без padding для header/payload
    const header = encoding.b64encode(
        JSON.stringify({ alg: "HS256", typ: "JWT" }),
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

    // подпись сразу в base64url без '='
    const signature = crypto.hmac(
        "sha256",
        secret,
        signingInput,
        "base64rawurl", // ← корректное значение
    );

    return `${signingInput}.${signature}`;
}

export default function () {
    const jwt = genJwt();
    http.get("http://localhost:8080/api/ping", {
        headers: { Authorization: `Bearer ${jwt}` },
    });
}
