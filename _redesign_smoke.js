"use strict";
const assert = require("assert");
const fs = require("fs");

const html = fs.readFileSync("app/workbench.html", "utf8");
const scriptMatch = Array.from(html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/gi))
  .find((match) => !/type=["']importmap["']/i.test(match[1]) && !/\bsrc=/i.test(match[1]));
assert(scriptMatch, "inline workbench application script must exist");
const script = scriptMatch[2];
new Function(script);

function getFunction(name) {
  const start = script.indexOf("function " + name + "(");
  assert(start >= 0, "missing function " + name);
  const end = script.indexOf("\n}", start);
  assert(end >= 0, "unterminated function " + name);
  return script.slice(start, end + 2);
}

const escSource = script.match(/function esc\(s\)\{[^}]+\}/);
const escAttrSource = script.match(/function escAttr\(s\)\{[^}]+\}/);
assert(escSource && escAttrSource, "HTML escaping helpers must exist");
const esc = new Function("return (" + escSource[0] + ")")();
const escAttr = new Function("esc", "return (" + escAttrSource[0] + ")")(esc);
assert.strictEqual(esc("<tag>&"), "&lt;tag&gt;&amp;");
assert.strictEqual(escAttr('" onmouseover="x'), "&quot; onmouseover=&quot;x");

function captureConfirmCall(name, arg) {
  let captured;
  const fn = new Function("confirmBox", "post", "toast", "loadTrash",
    getFunction(name) + "; return " + name + ";")(
    function () { captured = Array.from(arguments); },
    function () { return Promise.resolve({}); },
    function () {},
    function () {}
  );
  fn(arg);
  assert.strictEqual(typeof captured[2], "function", name + " must pass a callback as argument 3");
  assert.strictEqual(captured[3], true, name + " must mark destructive confirmation");
  return captured[2];
}
captureConfirmCall("purgeTrash", "trash-id");
captureConfirmCall("emptyTrash");

const ledgerStart = script.indexOf("function u3RenderLedger(");
const ledgerEnd = script.indexOf("/* R5", ledgerStart);
assert(ledgerStart >= 0 && ledgerEnd > ledgerStart, "ledger renderer must exist");
const renderLedger = new Function("$", "esc", "escAttr",
  script.slice(ledgerStart, ledgerEnd) + "; return u3RenderLedger;")(
  function (id) { return id === "pfwLedgerSub" ? { textContent: "" } : null; }, esc, escAttr
);
const ledgerEl = { innerHTML: "" };
renderLedger(ledgerEl, {
  exists: true,
  total: 1,
  path: "story/particle_ledger.md",
  rows: [{ name: "balance", cols: { begin: "1", inc: "0", spend: "0", end: "1", note: '" onmouseover="alert(1)' } }]
});
assert(ledgerEl.innerHTML.includes("&quot; onmouseover=&quot;alert(1)"), "ledger tooltip must escape attribute quotes");
assert(!ledgerEl.innerHTML.includes('onclick="'), "ledger rows must remain read-only and non-clickable");
assert(!ledgerEl.innerHTML.includes("openDoc"), "ledger must not fall back to raw-document rendering");

const simsStart = script.indexOf("function loadSims()");
const simsEnd = script.indexOf("\nfunction ", simsStart + 1);
const loadSims = script.slice(simsStart, simsEnd);
assert(!loadSims.includes("/api/overview"), "simulation list should not request an unused overview payload");
assert(getFunction("readChapter").includes(".catch("), "chapter reader must surface failed requests");

// Creature primary path is the skinned GLB; the procedural mesh remains only as a fallback.
assert(script.includes('D.name="shenlong-flight-root"'), "Shenlong GLB root must exist");
assert(script.includes("D.userData.mixer.update(dt)"), "flight pose must advance the GLB AnimationMixer");
assert(script.includes('return /01_Flight_Coiling/i.test(c.name)')
  && script.includes('return /02_Cloud_Rise/i.test(c.name)')
  && script.includes('return /03_Jade_Roar/i.test(c.name)'),
  "flight, cloud-rise, and roar clips must be selected by name");
assert(script.includes("function u3PlayDragonAction("), "named one-shot dragon actions must be playable");
assert(script.includes('D.name="taotie-flight-creature"') && script.includes("u3CreateProceduralDevourerFallback()"),
  "procedural fallback must remain available when the GLB fails");
assert(script.includes("dragonLoadState"), "load state must gate the GLB actions");

// The primary model is an original skinned GLB with three named clips.
assert(html.includes('"three":"/vendor/three160/build/three.module.js"'), "GLTF import map must target the pinned Three.js module");
assert(script.includes('loader.load("assets/shenlong/shenlong_original.glb"'), "workbench must load the original Shenlong GLB");
assert(script.includes("new THREE.AnimationMixer(gltf.scene)"), "GLB clips must use an AnimationMixer");
// Object3D.lookAt points +Z at the target; the adapter must map the Blender +X head there.
assert(script.includes("model.rotation.y=-Math.PI/2"), "model adapter must map the head onto the +Z lookAt forward");
assert(script.includes("rootQ.clone().invert().multiply(U3.devourerHeadingQ)"), "world heading must be converted into the tilted root's local frame");
const glb = fs.readFileSync("app/assets/shenlong/shenlong_original.glb");
assert.strictEqual(glb.toString("ascii", 0, 4), "glTF", "Shenlong asset must be a binary GLB");
let offset = 12, gltfDoc;
while (offset < glb.length) {
  const length = glb.readUInt32LE(offset), type = glb.readUInt32LE(offset + 4);
  offset += 8;
  if (type === 0x4e4f534a) gltfDoc = JSON.parse(glb.toString("utf8", offset, offset + length));
  offset += length;
}
assert(gltfDoc && gltfDoc.skins && gltfDoc.skins[0].joints.length >= 30, "GLB must carry an articulated skin");
const clips = (gltfDoc.animations || []).map((clip) => clip.name);
assert.deepStrictEqual(clips, ["01_Flight_Coiling", "02_Cloud_Rise", "03_Jade_Roar"]);
assert(gltfDoc.meshes.length >= 45, "original asset should include modeled detail meshes");

// ---- 创作前访谈：无密钥提示不得把用户指向点不到的入口或假的免模型旁路 ----
assert(!html.includes("请先在左下角") && !script.includes("请先在左下角"),
  "error copy must not point at the sidebar key entry (covered by the galaxy screen / modal mask)");
assert(!html.includes("该方式不调用模型"), "manual brief must not claim model-free book creation");
assert(html.includes('id="ivKeyBar"') && /id="ivKeyBar"[\s\S]{0,400}onclick="openKey\(\)"/.test(html),
  "interview panel must carry its own clickable key entry");
assert(script.includes("function ivSyncKeyBar(") && script.includes("IV_KEY_OK=ok"),
  "the key bar must follow the real backend key_status");
assert(script.includes("请点上方「🔑 配置密钥」"), "no-key errors must point at the in-panel key button");
assert(script.includes('openCreateBook({title:"",brief:ivManualBrief()'),
  "the manual fallback must pass a prefill object, not a bare brief string");
const zKey = Number((html.match(/#keyModal\{[^}]*z-index:(\d+)/) || [])[1]);
const zMask = Number((html.match(/\.modal-mask\{[^}]*z-index:(\d+)/) || [])[1]);
assert(zKey > zMask, "the key modal must stack above the interview modal so its fields stay clickable");

console.log("Workbench, original Shenlong GLB, rig, and three animation smoke checks passed");
