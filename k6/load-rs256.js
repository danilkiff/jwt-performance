import http from "k6/http";

export const options = {
    vus: 200,
    duration: "60s",
};

const tokens = open("../output/rs256-tokens.txt").trim().split("\n");
const n = tokens.length;

function randomToken() {
    const i = Math.floor(Math.random() * n);
    return tokens[i];
}

export default function () {
    const token = randomToken();
    http.get("http://localhost:8080/api/ping", {
        headers: { Authorization: `Bearer ${token}` },
    });
}
