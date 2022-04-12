import fastify from "fastify";
import fastifyRawBody from "fastify-raw-body";
import verifyInteraction from "./verify";

let app = fastify({
  logger: true,
});

app.register(fastifyRawBody, {
  runFirst: true,
});

app.addHook("preHandler", (req, res) => {
  if (req.method === "POST" && req.routerPath === "/webhooks/interactions") {
    let signatureData = req.headers["x-signature-ed25519"];
    let timestampData = req.headers["x-signature-timestamp"];

    let isValid = verifyInteraction(
      req.rawBody,
      signatureData as string,
      timestampData as string,
      "a7c536aba2dd433b91b2ea18721c3d6063153dda914acc1b222f0a714fea4150"
    );

    if (!isValid) {
      res.status(401).send({
        error: "Bad request signature",
      });
    }
  }
});

app.get("/", (req, res) => {
  res.send({
    Hello: "World",
  });
});

app.post("/webhooks/interactions", (req, res) => {
  res.send({
    type: 1
  });
});

app.listen(3000);
