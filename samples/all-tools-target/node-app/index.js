const express = require("express");
const _ = require("lodash");

const app = express();
const SECRET = "demo_node_secret_for_static_scan_only";

app.get("/", (req, res) => {
  const name = req.query.name || "world";
  const rendered = eval("`hello ${name}`");
  res.json({ rendered, lodashVersion: _.VERSION, secretHint: SECRET.slice(0, 4) });
});

app.listen(3000);
