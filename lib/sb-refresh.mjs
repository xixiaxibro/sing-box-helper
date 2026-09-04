import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { performance } from "node:perf_hooks";

const home = os.homedir();
const configDir = process.env.SB_CONFIG_DIR || path.join(home, ".config", "sing-box");
const stateDir = process.env.SB_STATE_DIR || path.join(home, ".local", "state", "sing-box");
const configPath = path.join(configDir, "config.json");
const backupPath = path.join(configDir, "config.json.bak");
const nodesPath = path.join(configDir, "nodes.json");
const urlPath = path.join(configDir, "subscription.url");
const defaultTestUrl = "https://www.gstatic.com/generate_204";

const args = process.argv.slice(2);
const positional = args.filter((arg) => !arg.startsWith("--"));
const urlArg = positional[0] || null;

const slug = (value) =>
  value
    .normalize("NFKD")
    .replace(/[^\w\s-]/g, "")
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "") || "node";

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writePrivate(file, contents) {
  fs.writeFileSync(file, contents, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function cleanBase64(text) {
  const cleaned = [...text]
    .filter((ch) => /[A-Za-z0-9+/_=-]/.test(ch))
    .join("")
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  return cleaned + "=".repeat((4 - (cleaned.length % 4 || 4)) % 4);
}

function decodeSubscription(text) {
  return Buffer.from(cleanBase64(text), "base64").toString("utf8");
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseTrojanLinks(decodedText) {
  const lines = decodedText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const seen = new Map();
  for (const line of lines) {
    if (!line.startsWith("trojan://")) continue;

    let url;
    try {
      url = new URL(line);
    } catch {
      continue;
    }

    const host = url.hostname;
    const port = Number(url.port || 443);
    const password = safeDecodeURIComponent(url.username);
    if (!host || !Number.isFinite(port) || !password) continue;

    const label = safeDecodeURIComponent(url.hash.replace(/^#/, "")) || `${host}:${port}`;
    const peer =
      url.searchParams.get("peer") ||
      url.searchParams.get("sni") ||
      url.searchParams.get("serverName") ||
      "";
    const insecureValue =
      url.searchParams.get("allowInsecure") ||
      url.searchParams.get("skip-cert-verify") ||
      "";
    const insecure = /^(?:1|true)$/i.test(insecureValue);
    const key = `${host}:${port}:${peer}:${label}`;

    if (!seen.has(key)) {
      seen.set(key, { label, host, port, peer, password, insecure });
    }
  }
  return [...seen.values()];
}

function probeNode(node, timeoutMs = 3500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const started = performance.now();
    let done = false;

    const finish = (ok, error = null) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({
        ...node,
        ok,
        latency_ms: Math.round(performance.now() - started),
        error,
      });
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false, "timeout"));
    socket.once("error", (error) => finish(false, error.message));
    socket.connect(node.port, node.host);
  });
}

async function probeAll(nodes, concurrency = 6) {
  const results = [];
  let index = 0;

  async function worker() {
    while (index < nodes.length) {
      const current = nodes[index++];
      results.push(await probeNode(current));
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, nodes.length) }, worker),
  );
  return results.sort((a, b) => a.latency_ms - b.latency_ms);
}

function buildOutbounds(liveNodes) {
  const usedTags = new Set();
  return liveNodes.map((node, index) => {
    let tag = `${slug(node.label)}-${node.host.replace(/\./g, "-")}-${node.port}`;
    if (usedTags.has(tag)) tag = `${tag}-${index + 1}`;
    usedTags.add(tag);
    return { ...node, tag };
  });
}

function isUsNode(node) {
  return /(?:美国|美國|\bUS\b|\bUSA\b)/i.test(node.label);
}

function buildConfig(outbounds) {
  let previousDefault = "auto";
  if (fs.existsSync(configPath)) {
    try {
      const current = JSON.parse(fs.readFileSync(configPath, "utf8"));
      const selector = (current.outbounds || []).find((item) => item.tag === "select");
      if (selector?.default) previousDefault = selector.default;
    } catch {
      previousDefault = "auto";
    }
  }

  const selectable = outbounds.map((node) => node.tag);
  const preferredSelectable = outbounds.filter(isUsNode).map((node) => node.tag);
  const autoSelectable = preferredSelectable.length > 0 ? preferredSelectable : selectable;
  const selectedDefault = selectable.includes(previousDefault) ? previousDefault : "auto";
  const trojanOutbounds = outbounds.map((node) => ({
    type: "trojan",
    tag: node.tag,
    server: node.host,
    server_port: node.port,
    password: node.password,
    tls: {
      enabled: true,
      server_name: node.peer,
      insecure: node.insecure,
    },
  }));

  return {
    log: { level: "info", timestamp: true },
    inbounds: [
      {
        type: "mixed",
        tag: "mixed-in",
        listen: "127.0.0.1",
        listen_port: 7890,
        set_system_proxy: true,
      },
    ],
    outbounds: [
      ...trojanOutbounds,
      {
        type: "urltest",
        tag: "auto",
        outbounds: autoSelectable,
        url: defaultTestUrl,
        interval: "10m",
        tolerance: 100,
      },
      {
        type: "selector",
        tag: "select",
        outbounds: ["auto", ...selectable],
        default: selectedDefault,
      },
      { type: "direct", tag: "direct" },
    ],
    route: { auto_detect_interface: true, final: "select" },
  };
}

async function main() {
  ensureDir(configDir);
  ensureDir(stateDir);

  if (urlArg) writePrivate(urlPath, `${urlArg}\n`);
  if (!fs.existsSync(urlPath)) {
    throw new Error(`Missing subscription URL file: ${urlPath}`);
  }

  const subscriptionUrl = fs.readFileSync(urlPath, "utf8").trim();
  if (!subscriptionUrl) {
    throw new Error(`Subscription URL is empty: ${urlPath}`);
  }

  const response = await fetch(subscriptionUrl, {
    signal: AbortSignal.timeout(15000),
    headers: { "user-agent": "sb-refresh/1.0" },
  });
  if (!response.ok) {
    throw new Error(
      `Subscription request failed: ${response.status} ${response.statusText}`,
    );
  }

  const nodes = parseTrojanLinks(decodeSubscription(await response.text()));
  if (nodes.length === 0) {
    throw new Error("No Trojan nodes found in subscription");
  }

  const probed = await probeAll(nodes);
  const liveNodes = probed.filter((node) => node.ok);
  if (liveNodes.length === 0) {
    throw new Error("No reachable Trojan nodes found");
  }

  const mapped = buildOutbounds(liveNodes);
  const preferredTags = mapped.filter(isUsNode).map((node) => node.tag);
  const config = buildConfig(mapped);

  if (fs.existsSync(configPath)) fs.copyFileSync(configPath, backupPath);
  writePrivate(configPath, `${JSON.stringify(config, null, 2)}\n`);

  const nodesState = {
    updated_at: new Date().toISOString(),
    total_candidates: nodes.length,
    reachable_candidates: liveNodes.length,
    selected_strategy: preferredTags.length > 0 ? "urltest-us-first" : "urltest-any",
    preferred_region: preferredTags.length > 0 ? "US" : "any",
    preferred_tags: preferredTags,
    test_url: defaultTestUrl,
    nodes: mapped.map(({ password, ...node }) => node),
  };
  writePrivate(nodesPath, `${JSON.stringify(nodesState, null, 2)}\n`);

  console.log(
    `Subscription refreshed: ${liveNodes.length}/${nodes.length} nodes reachable`,
  );
  for (const node of mapped.slice(0, 12)) {
    console.log(`${node.tag}\t${node.latency_ms}ms\t${node.label}`);
  }
  console.log("Run sb-up or sb-use to apply the new configuration.");
}

main().catch((error) => {
  console.error(`sb-refresh failed: ${error.message}`);
  process.exit(1);
});
