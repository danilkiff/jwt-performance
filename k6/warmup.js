import http from "k6/http";
import {SharedArray} from "k6/data";

const ITERATIONS = 2000;
const PING_CRYPT = "http://localhost:8080/api/ping";
const PING_PLAIN = "http://localhost:8080/plain/api/ping";

export const options = {
    scenarios: {
        hs256: { executor: "per-vu-iterations", vus: 10, iterations: ITERATIONS, exec: "hs256" },
        rs256: { executor: "per-vu-iterations", vus: 10, iterations: ITERATIONS, exec: "rs256" },
        es256: { executor: "per-vu-iterations", vus: 10, iterations: ITERATIONS, exec: "es256" },
        jwe:   { executor: "per-vu-iterations", vus: 10, iterations: ITERATIONS, exec: "jwe"   },
        plain: { executor: "per-vu-iterations", vus: 10, iterations: ITERATIONS, exec: "plain" },
    }
};

const hsTokens  = new SharedArray("hs256", () => open("../output/hs256-tokens.txt").trim().split("\n"));
const rsTokens  = new SharedArray("rs256", () => open("../output/rs256-tokens.txt").trim().split("\n"));
const esTokens  = new SharedArray("es256", () => open("../output/es256-tokens.txt").trim().split("\n"));
const jweTokens = new SharedArray("jwe",   () => open("../output/jwe-tokens.txt").trim().split("\n"));

function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

export function hs256() {
    http.get(PING_CRYPT, {headers: {Authorization: `Bearer ${pick(hsTokens)}`}});
}

export function rs256() {
    http.get(PING_CRYPT, {headers: {Authorization: `Bearer ${pick(rsTokens)}`}});
}

export function es256() {
    http.get(PING_CRYPT, {headers: {Authorization: `Bearer ${pick(esTokens)}`}});
}

export function jwe() {
    http.get(PING_CRYPT, {headers: {Authorization: `Bearer ${pick(jweTokens)}`}});
}

export function plain() {
    http.get(PING_PLAIN);
}
