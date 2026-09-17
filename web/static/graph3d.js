'use strict';
/* Inbound Graph 3D (#graph). Every particle is one real inbound FortiGate log line.
   Inside the glass sphere: services your rules really expose. Outside ring: closed ports being knocked on.
   Top beacon: traffic aimed at the firewall itself. Hover a particle for a preview, click it to capture that exact request
   (original log fields + Investigation Tracker). Three.js r147 is loaded on demand from /static/vendor/three. */

// kinds: 0 allowed · 1 closed port · 2 open port, source not allowed · 3 deny rule · 4 firewall itself · 5 security block · 6 IPS
const KIND = [
  {name: 'Allowed', short: 'ALLOWED', col: 0x4da3ff, css: '#4da3ff', tip: 'A rule allowed it - it passes through the glass to its service.'},
  {name: 'Denied · closed port', short: 'DENIED', col: 0xff4d4d, css: '#ff4d4d', tip: 'No rule opens this port. The request bounces off a red door on the outer ring. Mostly internet scanners.'},
  {name: 'Denied · source not allowed', short: 'DENIED', col: 0xff8a3d, css: '#ff8a3d', tip: 'The port IS open, but only for other sources (e.g. certain countries or IPs). It hits the glass in front of the service it wanted.'},
  {name: 'Denied · deny rule', short: 'DENIED', col: 0xff2e7a, css: '#ff2e7a', tip: 'An explicit deny rule (e.g. an attacker/country block list) matched it.'},
  {name: 'Denied · firewall itself', short: 'DENIED', col: 0xff5ec8, css: '#ff5ec8', tip: 'Aimed at the FortiGate itself (admin, VPN, telnet…). Stopped by local-in policy at the beacon on top.'},
  {name: 'Blocked by security profile', short: 'BLOCKED', col: 0xffd24d, css: '#ffd24d', tip: 'A rule allowed the port but application control / IPS stopped the session inside the firewall.'},
  {name: 'IPS threat', short: 'THREAT', col: 0x9d7bff, css: '#9d7bff', tip: 'An intrusion-prevention signature matched (exploit attempt).'},
];
const kindOf = (v, why) => v === 0 ? 0 : v === 1 ? Math.min(4, Math.max(1, why || 1)) : v === 2 ? 5 : 6;
const G3 = {mode: 'live', speed: 1, playing: true, show: KIND.map(() => true), autoRotate: true, labels: true, timeScale: 1,
  fired: 0, seq: 0, feed: [], focusKind: null};
const RS = 105, RF = 22, RO = 12.5, RD = RF + 11, MAXP = 6000, DOORS = 14;
const COUNTRY_LL = {
  'United States': [39, -98], 'Canada': [57, -101], 'Mexico': [23, -102], 'Brazil': [-10, -52], 'Argentina': [-34, -64], 'Chile': [-33, -71],
  'Colombia': [4, -73], 'Peru': [-9, -75], 'Venezuela': [7, -66], 'United Kingdom': [54, -2], 'Ireland': [53, -8], 'France': [46, 2],
  'Germany': [51, 10], 'Netherlands': [52, 5.5], 'Belgium': [50.6, 4.6], 'Luxembourg': [49.8, 6.1], 'Switzerland': [46.8, 8.2],
  'Austria': [47.5, 14.5], 'Italy': [42.8, 12.5], 'Spain': [40, -4], 'Portugal': [39.5, -8], 'Poland': [52, 19], 'Czech Republic': [49.8, 15.5],
  'Czechia': [49.8, 15.5], 'Slovakia': [48.7, 19.7], 'Hungary': [47.1, 19.4], 'Romania': [45.9, 25], 'Bulgaria': [42.7, 25.5],
  'Greece': [39, 22], 'Serbia': [44, 21], 'Croatia': [45.1, 15.2], 'Ukraine': [49, 32], 'Moldova, Republic of': [47, 28.8],
  'Moldova': [47, 28.8], 'Belarus': [53.7, 28], 'Russian Federation': [60, 95], 'Russia': [60, 95], 'Lithuania': [55.2, 23.9],
  'Latvia': [56.9, 24.6], 'Estonia': [58.6, 25], 'Finland': [64, 26], 'Sweden': [62, 15], 'Norway': [61, 9], 'Denmark': [56, 10],
  'Iceland': [65, -18], 'Turkey': [39, 35], 'Israel': [31, 35], 'Iran, Islamic Republic of': [32, 53], 'Iran': [32, 53], 'Iraq': [33, 44],
  'Saudi Arabia': [24, 45], 'United Arab Emirates': [24, 54], 'Qatar': [25.3, 51.2], 'Kuwait': [29.3, 47.5], 'Oman': [21, 57],
  'Pakistan': [30, 70], 'Afghanistan': [33, 65], 'India': [22, 79], 'Bangladesh': [24, 90], 'Sri Lanka': [7.9, 80.7], 'Nepal': [28.4, 84.1],
  'China': [35, 103], 'Hong Kong': [22.3, 114.2], 'Taiwan': [23.7, 121], 'Japan': [36, 138], 'Korea, Republic of': [36.5, 127.8],
  'South Korea': [36.5, 127.8], 'Mongolia': [46.9, 103.8], 'Viet Nam': [16, 107], 'Vietnam': [16, 107], 'Thailand': [15, 101],
  'Cambodia': [12.6, 105], 'Malaysia': [4, 102], 'Singapore': [1.35, 103.8], 'Indonesia': [-2, 118], 'Philippines': [12.9, 122],
  'Australia': [-25, 134], 'New Zealand': [-41, 174], 'South Africa': [-29, 24], 'Nigeria': [9, 8], 'Egypt': [26.8, 30.8],
  'Morocco': [31.8, -7.1], 'Kenya': [0, 38], 'Ghana': [7.9, -1], 'Algeria': [28, 2], 'Tunisia': [34, 9], 'Ethiopia': [9, 40],
  'Kazakhstan': [48, 67], 'Uzbekistan': [41, 64], 'Azerbaijan': [40.1, 47.6], 'Georgia': [42.3, 43.4], 'Armenia': [40.1, 45],
  'Seychelles': [-4.7, 55.5], 'Panama': [8.5, -80], 'Costa Rica': [9.7, -83.8], 'Ecuador': [-1.8, -78.2], 'Bolivia': [-16.3, -63.6],
  'Uruguay': [-32.5, -55.8], 'Cyprus': [35.1, 33.4], 'Malta': [35.9, 14.4], 'Slovenia': [46.1, 14.9], 'Albania': [41.2, 20.2],
  'Reserved': [85, 0],
};
let _a, _b, _c, _d;                                             // scratch vectors, created once THREE is loaded

function loadScript(src) {
  return new Promise((res, rej) => {
    if (document.querySelector(`script[src="${src}"]`)) return res();
    const s = document.createElement('script');
    s.src = src; s.onload = res; s.onerror = () => rej(new Error('cannot load ' + src));
    document.head.appendChild(s);
  });
}
async function ensureThree() {
  if (window.THREE && THREE.UnrealBloomPass && THREE.OrbitControls) return;
  const b = '/static/vendor/three/';
  await loadScript(b + 'three.min.js');
  for (const f of ['OrbitControls', 'CopyShader', 'LuminosityHighPassShader', 'EffectComposer', 'RenderPass', 'ShaderPass', 'MaskPass', 'UnrealBloomPass'])
    await loadScript(b + f + '.js');
}
function llVec(lat, lon, r) {
  const phi = (90 - lat) * Math.PI / 180, th = (lon + 180) * Math.PI / 180;
  return new THREE.Vector3(-r * Math.sin(phi) * Math.cos(th), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(th));
}
function countryVec(name, r) {
  let ll = COUNTRY_LL[name];
  if (!ll) {
    let h = 0; for (const ch of name || '?') h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    ll = [((h % 1400) / 10) - 70, ((h >> 11) % 3600) / 10 - 180];
  }
  return llVec(ll[0], ll[1], r);
}
const g3Svc = port => (G3.services || []).find(s => s.port === port);
const g3PortName = port => (g3Svc(port) || {}).title || (G3.portTitles || {})[port] || `port ${port}`;
const g3Rule = pid => pid === null || pid === undefined ? '' : polLabel(pid);

// ------------------------------------------------------------------ page
PAGES.graph = {
  layout: () => `<div class="g3" id="g3">
    <canvas id="g3-canvas"></canvas><div class="g3-labels" id="g3-labels"></div>
    <div class="g3-left">
      <div class="g3-hud g3-status">
        <div class="g3-mode"><span class="g3-dot"></span><b id="g3-mode">LIVE</b><span id="g3-clock" class="mono"></span></div>
        <div class="g3-fire"><span class="bolt">⚡</span><div><b id="g3-rps">0</b><span> requests / second</span>
          <div class="muted" id="g3-fired">0 requests fired since you opened this view</div></div></div>
        <canvas id="g3-spark"></canvas>
        <div class="g3-counts">
          <div class="c allow"><b id="g3-n0">0</b><span>allowed</span></div><div class="c deny"><b id="g3-n1">0</b><span>denied</span></div>
          <div class="c utm"><b id="g3-n2">0</b><span>sec. blocks</span></div><div class="c threat"><b id="g3-n3">0</b><span>IPS threats</span></div>
        </div>
        <div class="g3-sub" id="g3-sub">connecting…</div>
      </div>
      <div class="g3-hud g3-why"><h4>Why was it denied? <span class="muted" id="g3-why-win"></span></h4><div id="g3-why"></div></div>
      <div class="g3-hud g3-feedbox"><h4>Live requests <span class="muted">click one to capture it</span></h4><div id="g3-feed" class="g3-feed"></div></div>
    </div>
    <div class="g3-hud g3-side" id="g3-side">
      <div class="g3-sec"><h4>Ports under fire</h4><div id="g3-ports"></div></div>
      <div class="g3-sec"><h4>Applications</h4><div id="g3-apps"></div></div>
      <div class="g3-sec"><h4>Top attackers</h4><div id="g3-att"></div></div>
      <div class="g3-sec"><h4>Countries</h4><div id="g3-ctry"></div></div>
      <div class="g3-sec" id="g3-thr-sec"><h4>IPS threats</h4><div id="g3-thr"></div></div>
    </div>
    <div class="g3-toasts" id="g3-toasts"></div>
    <div class="g3-hover" id="g3-hover" hidden></div>
    <div class="g3-hud g3-req" id="g3-req" hidden></div>
    <div class="g3-hud g3-time">
      <div class="g3-legend">
        ${KIND.map((k, i) => `<label title="${esc(k.tip)}"><input type="checkbox" data-k="${i}" checked><i style="background:${k.css};color:${k.css}"></i>${k.name.replace('Denied · ', '')}</label>`).join('')}
        <div class="g3-tools"><label><input type="checkbox" id="g3-rot" checked>rotate</label><label><input type="checkbox" id="g3-lbl" checked>labels</label>
          <button id="g3-reset">reset view</button></div>
      </div>
      <div class="g3-ctl">
        <button id="g3-live" class="g3-livebtn on" title="Back to live">● LIVE</button>
        <button id="g3-back" title="Back 1 minute">⏮</button><button id="g3-play" title="Play / pause">⏸</button>
        <button id="g3-fwd" title="Forward 1 minute">⏭</button>
        <div class="seg small" id="g3-speed">${[1, 5, 20, 60].map(s => `<button data-s="${s}" class="${s === 1 ? 'on' : ''}">${s}×</button>`).join('')}</div>
        <button id="g3-freeze" class="g3-freeze" title="Freeze every particle so you can click one">❄ Freeze</button>
        <button id="g3-slow" title="Slow motion">🐢 Slow-mo</button>
        <button id="g3-next" title="Jump to the next attack marker">⚑ next attack</button>
        <span class="g3-tlabel mono" id="g3-tlabel"></span><span class="grow"></span><span class="g3-note" id="g3-note"></span>
        <button id="g3-fs" class="g3-fs" title="Full screen (F) · Esc to exit · Space = freeze">⛶ Full screen</button>
      </div>
      <div class="g3-track" id="g3-track"><canvas id="g3-tl"></canvas><div class="g3-head" id="g3-head"></div><div class="g3-tip" id="g3-tip" hidden></div></div>
    </div>
  </div>`,
  async load(sp) {
    try { await ensureThree(); } catch (e) {
      $('#g3').innerHTML = `<div class="empty" style="padding:60px">3D engine could not be loaded: ${esc(e.message)}</div>`; return;
    }
    if (!G3.scene || G3.canvas !== $('#g3-canvas')) initScene();
    if (!G3.scene) return;
    G3.sp = sp;
    const [meta] = await Promise.all([api('/api/graph3d/meta'), g3LoadTimeline(sp)]);
    G3.services = meta.services;
    buildServices(meta.services);
    bindControls();
    if (G3.mode === 'live') startLive(); else startReplay(G3.playTime || sp.to - 600_000);
  },
};

// ------------------------------------------------------------------ scene
function initScene() {
  if (G3.renderer) teardown();
  [_a, _b, _c, _d] = [0, 0, 0, 0].map(() => new THREE.Vector3());
  const canvas = $('#g3-canvas');
  let renderer;
  try { renderer = new THREE.WebGLRenderer({canvas, antialias: true, powerPreference: 'high-performance'}); } catch (e) {
    $('#g3').insertAdjacentHTML('beforeend', '<div class="empty" style="position:absolute;inset:40%">WebGL is not available in this browser.</div>'); return;
  }
  const w = canvas.clientWidth, h = canvas.clientHeight;
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.setSize(w, h, false);
  renderer.setClearColor(0x04060a, 1);
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x04060a, 0.0022);
  const camera = new THREE.PerspectiveCamera(48, w / h, 0.1, 3000);
  camera.position.set(0, 30, 132);
  const controls = new THREE.OrbitControls(camera, canvas);
  Object.assign(controls, {enableDamping: true, dampingFactor: 0.06, autoRotate: true, autoRotateSpeed: 0.3, minDistance: 25, maxDistance: 420});
  const composer = new THREE.EffectComposer(renderer);
  composer.addPass(new THREE.RenderPass(scene, camera));
  composer.addPass(new THREE.UnrealBloomPass(new THREE.Vector2(w, h), 1.1, 0.55, 0.12));
  Object.assign(G3, {canvas, renderer, scene, camera, controls, composer, orbs: {}, doors: {}, bursts: [], queue: [], countryDots: {},
    fwLabel: null, animT: 0, feed: [], sel: null});

  const sg = new THREE.BufferGeometry(), sp = [];
  for (let i = 0; i < 1800; i++) { const v = new THREE.Vector3().randomDirection().multiplyScalar(700 + Math.random() * 600); sp.push(v.x, v.y, v.z); }
  sg.setAttribute('position', new THREE.Float32BufferAttribute(sp, 3));
  scene.add(new THREE.Points(sg, new THREE.PointsMaterial({color: 0x7f9fd8, size: 1.3, sizeAttenuation: false, transparent: true, opacity: 0.55})));

  // source globe graticule
  const lineMat = new THREE.LineBasicMaterial({color: 0x3a6fb8, transparent: true, opacity: 0.09});
  for (let lat = -60; lat <= 60; lat += 30) {
    const pts = []; for (let lon = -180; lon <= 180; lon += 6) pts.push(llVec(lat, lon, RS));
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), lineMat));
  }
  for (let lon = -180; lon < 180; lon += 30) {
    const pts = []; for (let lat = -84; lat <= 84; lat += 6) pts.push(llVec(lat, lon, RS));
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), lineMat));
  }

  // firewall glass
  const fres = new THREE.ShaderMaterial({
    uniforms: {uColor: {value: new THREE.Color(0x3d8bff)}, uPulse: {value: 0}, uAlert: {value: 0}},
    vertexShader: `varying vec3 vN; varying vec3 vV;
      void main(){ vec4 mv = modelViewMatrix * vec4(position,1.0); vN = normalize(normalMatrix * normal); vV = normalize(-mv.xyz); gl_Position = projectionMatrix * mv; }`,
    fragmentShader: `uniform vec3 uColor; uniform float uPulse; uniform float uAlert; varying vec3 vN; varying vec3 vV;
      void main(){ float f = pow(1.0 - abs(dot(vN, vV)), 2.6); vec3 c = mix(uColor, vec3(1.0,0.3,0.35), uAlert);
        gl_FragColor = vec4(c, 0.025 + f * (0.62 + uPulse)); }`,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  scene.add(new THREE.Mesh(new THREE.SphereGeometry(RF, 96, 96), fres));
  const shell = new THREE.LineSegments(new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(RF * 1.004, 3)),
    new THREE.LineBasicMaterial({color: 0x4d8fe0, transparent: true, opacity: 0.07}));
  scene.add(shell);
  const rings = new THREE.Group();
  for (let i = -3; i <= 3; i++) {
    const y = i * RF / 4.2, r = Math.sqrt(RF * RF - y * y);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(r, 0.035, 6, 160), new THREE.MeshBasicMaterial({color: 0x5aa2ff, transparent: true, opacity: 0.2}));
    ring.rotation.x = Math.PI / 2; ring.position.y = y; rings.add(ring);
  }
  scene.add(rings);
  // closed-port ring (doors live on it)
  const doorRing = new THREE.Mesh(new THREE.TorusGeometry(RD, 0.08, 8, 260), new THREE.MeshBasicMaterial({color: 0xff4d4d, transparent: true, opacity: 0.22}));
  doorRing.rotation.x = Math.PI / 2;
  scene.add(doorRing);
  // firewall-itself beacon
  const beaconPos = new THREE.Vector3(0, RF + 6, 0);
  const beacon = new THREE.Mesh(new THREE.OctahedronGeometry(1.8, 0), new THREE.MeshBasicMaterial({color: KIND[4].col, wireframe: true}));
  beacon.position.copy(beaconPos);
  const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.06, 0.06, 6, 8), new THREE.MeshBasicMaterial({color: KIND[4].col, transparent: true, opacity: 0.4}));
  beam.position.set(0, RF + 3, 0);
  scene.add(beacon, beam);
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(2.6, 1), new THREE.MeshBasicMaterial({color: 0x9cc8ff, wireframe: true}));
  const coreGlow = new THREE.Mesh(new THREE.SphereGeometry(1.5, 24, 24), new THREE.MeshBasicMaterial({color: 0x6fb0ff}));
  scene.add(core, coreGlow);
  Object.assign(G3, {fres, shell, rings, core, coreGlow, beacon, beaconPos, beaconHits: 0});

  // particles: head + 2 trail samples each
  const N = MAXP * 3, pg = new THREE.BufferGeometry();
  const pos = new Float32Array(N * 3), col = new Float32Array(N * 3), size = new Float32Array(N), alpha = new Float32Array(N);
  pg.setAttribute('position', new THREE.BufferAttribute(pos, 3).setUsage(THREE.DynamicDrawUsage));
  pg.setAttribute('pcolor', new THREE.BufferAttribute(col, 3).setUsage(THREE.DynamicDrawUsage));
  pg.setAttribute('psize', new THREE.BufferAttribute(size, 1).setUsage(THREE.DynamicDrawUsage));
  pg.setAttribute('palpha', new THREE.BufferAttribute(alpha, 1).setUsage(THREE.DynamicDrawUsage));
  pg.boundingSphere = new THREE.Sphere(new THREE.Vector3(), 600);
  const pm = new THREE.ShaderMaterial({
    vertexShader: `attribute float psize; attribute vec3 pcolor; attribute float palpha; varying vec3 vC; varying float vA;
      void main(){ vC = pcolor; vA = palpha; vec4 mv = modelViewMatrix * vec4(position,1.0); gl_PointSize = psize * (320.0 / -mv.z); gl_Position = projectionMatrix * mv; }`,
    fragmentShader: `varying vec3 vC; varying float vA;
      void main(){ vec2 c = gl_PointCoord - 0.5; float d = length(c); if (d > 0.5) discard; float a = smoothstep(0.5, 0.0, d);
        gl_FragColor = vec4(vC * (0.7 + a * 0.8), a * a * vA); }`,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const points = new THREE.Points(pg, pm);
  points.frustumCulled = false;
  scene.add(points);
  G3.points = points;
  G3.P = {pos, col, size, alpha, geo: pg, n: 0, free: [], s: new Float32Array(MAXP * 3), c: new Float32Array(MAXP * 3), e: new Float32Array(MAXP * 3),
    t0: new Float64Array(MAXP), dur: new Float32Array(MAXP), k: new Int8Array(MAXP).fill(-1), target: new Array(MAXP), ev: new Array(MAXP)};
  for (let i = MAXP - 1; i >= 0; i--) G3.P.free.push(i);

  for (let i = 0; i < 240; i++) {
    const m = new THREE.Mesh(new THREE.RingGeometry(0.55, 0.85, 40),
      new THREE.MeshBasicMaterial({color: 0xffffff, transparent: true, opacity: 0, side: THREE.DoubleSide, depthWrite: false, blending: THREE.AdditiveBlending}));
    m.visible = false; scene.add(m); G3.bursts.push({m, t0: 0, dur: 1, big: false});
  }
  // selection marker
  const selRing = new THREE.Mesh(new THREE.RingGeometry(1.6, 1.95, 48), new THREE.MeshBasicMaterial({color: 0xffffff, transparent: true, opacity: 0.95, side: THREE.DoubleSide, depthWrite: false}));
  selRing.visible = false; scene.add(selRing); G3.selRing = selRing;

  // pointer: hover preview + click capture
  const ray = new THREE.Raycaster(), mouse = new THREE.Vector2();
  ray.params.Points.threshold = 1.8;
  const pick = ev => {
    const r = canvas.getBoundingClientRect();
    mouse.set(((ev.clientX - r.left) / r.width) * 2 - 1, -((ev.clientY - r.top) / r.height) * 2 + 1);
    ray.setFromCamera(mouse, camera);
    let best = null;
    for (const hit of ray.intersectObject(points)) {
      const i = Math.floor(hit.index / 3);
      if (hit.index % 3 || G3.P.k[i] < 0 || !G3.show[G3.P.k[i]]) continue;
      if (!best || hit.distanceToRay < best.d) best = {i, d: hit.distanceToRay};
    }
    if (best) return {particle: best.i};
    const orb = ray.intersectObjects(Object.values(G3.orbs).map(o => o.mesh))[0];
    if (orb) return {orb: orb.object.userData.port};
    const door = ray.intersectObjects(Object.values(G3.doors).map(o => o.mesh))[0];
    if (door) return {door: door.object.userData.port};
    return null;
  };
  let hoverT = 0;
  canvas.addEventListener('mousemove', ev => {
    const now = performance.now();
    if (now - hoverT < 70) return;
    hoverT = now;
    const p = pick(ev), tip = $('#g3-hover');
    if (!tip) return;
    canvas.style.cursor = p ? 'pointer' : 'grab';
    if (p && p.particle !== undefined) {
      const {row, str} = G3.P.ev[p.particle];
      tip.hidden = false;
      tip.style.left = (ev.offsetX + 16) + 'px'; tip.style.top = (ev.offsetY + 12) + 'px';
      tip.innerHTML = previewHTML(row, str);
    } else tip.hidden = true;
  });
  canvas.addEventListener('mouseleave', () => { const t = $('#g3-hover'); if (t) t.hidden = true; });
  canvas.addEventListener('click', ev => {
    const p = pick(ev);
    if (!p) return;
    if (p.particle !== undefined) { const {row, str} = G3.P.ev[p.particle]; selectRequest(row, str, p.particle); }
    else if (p.orb !== undefined) showOrb(p.orb);
    else if (p.door !== undefined) showDoor(p.door);
  });
  new ResizeObserver(() => {
    if (!canvas.isConnected) return;
    const W = canvas.clientWidth, H = canvas.clientHeight;
    if (!W || !H) return;
    renderer.setSize(W, H, false); composer.setSize(W, H); camera.aspect = W / H; camera.updateProjectionMatrix();
    g3DrawTimeline();
  }).observe(canvas);
  const tb = $('.g3-time');                                   // side panels end just above the timeline bar, whatever its height
  new ResizeObserver(() => { if (tb.isConnected) $('#g3').style.setProperty('--g3-tb', (tb.offsetHeight + 22) + 'px'); }).observe(tb);
  G3.last = performance.now();
  const id = G3.loopId = (G3.loopId || 0) + 1;
  requestAnimationFrame(t => frame(t, id));
}

function g3Label(text, cls) {
  const el = document.createElement('div');
  el.className = 'g3-lbl ' + (cls || '');
  el.innerHTML = text;
  $('#g3-labels').appendChild(el);
  return el;
}

function buildServices(services) {
  Object.values(G3.orbs).forEach(o => { G3.scene.remove(o.mesh, o.halo); o.el.remove(); });
  G3.orbs = {};
  const list = services.slice(0, 22), n = list.length + 1, golden = Math.PI * (3 - Math.sqrt(5));
  const add = (svc, i) => {
    const y = 1 - (i + 0.5) / n * 2, r = Math.sqrt(1 - y * y), th = i * golden;
    const p = new THREE.Vector3(Math.cos(th) * r, y, Math.sin(th) * r).multiplyScalar(RO);
    const risk = {critical: 0xff4d4d, high: 0xff9a4d, medium: 0xfcc34d, low: 0x4da3ff}[svc.level] || 0x8899aa;
    const mesh = new THREE.Mesh(new THREE.SphereGeometry(0.9, 24, 24), new THREE.MeshBasicMaterial({color: 0x4da3ff, transparent: true, opacity: 0.95}));
    mesh.position.copy(p); mesh.userData.port = svc.port;
    const halo = new THREE.Mesh(new THREE.TorusGeometry(1.45, 0.07, 8, 48), new THREE.MeshBasicMaterial({color: risk, transparent: true, opacity: 0.75}));
    halo.position.copy(p);
    G3.scene.add(mesh, halo);
    const el = g3Label(`<b>:${svc.port}</b> ${esc(String(svc.title).replace(/\s*\(.*\)/, ''))}<span class="n"></span>`, 'orb');
    G3.orbs[svc.port] = {svc, mesh, halo, el, pos: p, allow: 0, block: 0, pulse: 0};
  };
  list.forEach(add);
  add({port: 'other', title: 'other open ports', level: 'none'}, list.length);
  if (!G3.fwLabel) G3.fwLabel = g3Label(`<b>${esc(((S.meta || {}).firewall || {}).name || 'FortiGate')}</b><span>${esc([((S.meta || {}).firewall || {}).model, 'inside = open services'].filter(Boolean).join(' · '))}</span>`, 'fw');
  if (!G3.beaconLabel) G3.beaconLabel = g3Label('<b>Firewall itself</b> <span class="n"></span>', 'beacon');
  if (!G3.ringLabel) G3.ringLabel = g3Label('outer ring = closed ports', 'ring');
}

function door(port, title) {
  let d = G3.doors[port];
  if (d) return d;
  const used = new Set(Object.values(G3.doors).map(x => x.slot));
  let slot = [...Array(DOORS).keys()].find(s => !used.has(s));
  if (slot === undefined) {                                   // recycle the least-recently hit door
    const old = Object.values(G3.doors).filter(x => x.port !== 'other').sort((a, b) => a.last - b.last)[0];
    if (!old) return null;
    G3.scene.remove(old.mesh, old.gate); old.el.remove(); delete G3.doors[old.port]; slot = old.slot;
  }
  const ang = slot / DOORS * Math.PI * 2;
  const pos = new THREE.Vector3(Math.cos(ang) * RD, 0, Math.sin(ang) * RD);
  const mesh = new THREE.Mesh(new THREE.BoxGeometry(1.3, 2.6, 0.35), new THREE.MeshBasicMaterial({color: 0xff4d4d, transparent: true, opacity: 0.85}));
  mesh.position.copy(pos); mesh.lookAt(0, 0, 0); mesh.userData.port = port;
  const gate = new THREE.Mesh(new THREE.TorusGeometry(2.1, 0.07, 6, 40), new THREE.MeshBasicMaterial({color: 0xff4d4d, transparent: true, opacity: 0.55}));
  gate.position.copy(pos); gate.lookAt(0, 0, 0);
  G3.scene.add(mesh, gate);
  const el = g3Label(`<b>:${esc(port)}</b> ${esc(title || g3PortName(port))} <span class="n"></span>`, 'door');
  d = G3.doors[port] = {port, slot, pos, mesh, gate, el, hits: 0, live: 0, last: performance.now(), pulse: 0, title};
  return d;
}

// ------------------------------------------------------------------ particles
function spawn(row, str, when) {
  const P = G3.P;
  const [t, ci, dpt, v, ai, src, attack, si, pid, why] = row;
  const k = kindOf(v, why);
  if (!G3.show[k] || !P.free.length) return;
  const i = P.free.pop();
  const country = str.countries[ci];
  const start = countryVec(country, RS).add(_d.set(Math.random() - .5, Math.random() - .5, Math.random() - .5).multiplyScalar(9));
  const dir = _a.copy(start).normalize();
  let end, ctrl, target = null;
  const jit = s => _d.set(Math.random() - .5, Math.random() - .5, Math.random() - .5).multiplyScalar(s);
  if (k === 0 || k === 5 || k === 6) {
    target = G3.orbs[dpt] || G3.orbs.other;
    end = k === 0 ? target.pos.clone() : target.pos.clone().normalize().multiplyScalar(k === 5 ? RF * 0.86 : RF);
    ctrl = _c.copy(dir).multiplyScalar(RF * 1.6).add(jit(10));
  } else if (k === 1) {
    target = G3.doors[dpt] || door('other', 'other closed ports');
    end = target.pos.clone();
    ctrl = _c.copy(start).add(end).multiplyScalar(0.5).add(jit(24));
  } else if (k === 2) {
    target = G3.orbs[dpt] || null;
    end = (target ? target.pos.clone() : dir.clone()).normalize().multiplyScalar(RF);
    ctrl = _c.copy(start).add(end).multiplyScalar(0.5).add(jit(22));
  } else if (k === 4) {
    target = {beacon: true};
    end = G3.beaconPos.clone().add(jit(1.2));
    ctrl = _c.copy(start).add(end).multiplyScalar(0.5).add(_d.set(0, 30, 0));
  } else {
    end = dir.clone().multiplyScalar(RF);
    ctrl = _c.copy(start).add(end).multiplyScalar(0.5).add(jit(22));
  }
  P.s.set([start.x, start.y, start.z], i * 3); P.c.set([ctrl.x, ctrl.y, ctrl.z], i * 3); P.e.set([end.x, end.y, end.z], i * 3);
  P.t0[i] = when; P.dur[i] = (k === 0 ? 2800 : 2300) * (0.85 + Math.random() * 0.3); P.k[i] = k; P.target[i] = target;
  P.ev[i] = {row, str, seq: ++G3.seq};
  P.n = Math.max(P.n, i + 1);
  G3.feed.unshift({row, str, seq: G3.seq, i});
  if (G3.feed.length > 300) G3.feed.length = 300;
  if (k === 6) toast(`☣ IPS threat: ${attack || 'signature'} from ${src || '?'} (${country}) → port ${dpt}`, 'threat');
}
function burst(p, color, big) {
  const b = G3.bursts.find(x => !x.m.visible);
  if (!b) return;
  b.m.visible = true; b.m.position.copy(p); b.m.lookAt(_b.copy(p).multiplyScalar(2));
  b.m.material.color.setHex(color); b.t0 = G3.animT; b.dur = big ? 1400 : 750; b.big = big;
}
function toast(text, cls) {
  const now = performance.now();
  if (G3.lastToast && now - G3.lastToast < 1200) return;
  G3.lastToast = now;
  const box = $('#g3-toasts'); if (!box) return;
  const el = document.createElement('div');
  el.className = 'g3-toast ' + cls; el.textContent = text;
  box.prepend(el);
  setTimeout(() => el.classList.add('out'), 5500); setTimeout(() => el.remove(), 6200);
  while (box.children.length > 4) box.lastChild.remove();
}

function teardown() {
  stopFeeds();
  try { G3.renderer.dispose(); G3.renderer.forceContextLoss(); } catch (e) { /* already gone */ }
  Object.assign(G3, {scene: null, renderer: null, fwLabel: null, beaconLabel: null, ringLabel: null, orbs: {}, doors: {}, countryDots: {}, queue: [], sel: null});
}

function frame(now, id) {
  if (id !== G3.loopId) return;
  if (!G3.canvas || !G3.canvas.isConnected) { teardown(); return; }
  requestAnimationFrame(t => frame(t, id));
  if (document.hidden) return;
  const realDt = Math.min(1000, now - G3.last), dt = Math.min(100, realDt); G3.last = now;
  G3.animT += dt * G3.timeScale;
  const at = G3.animT, P = G3.P;
  if (G3.mode === 'replay' && G3.playing) G3.playTime += realDt * G3.speed * G3.timeScale;
  // live + freeze/slow-mo: hold the playback clock back so nothing is spawned ahead of the slowed animation
  G3.hold = G3.timeScale < 1 ? (G3.hold || 0) + realDt * (1 - G3.timeScale) : 0;
  const play = G3.mode === 'live' ? Date.now() - (G3.lag || 4000) - G3.hold : G3.playTime;
  let spawned = 0;
  if (G3.timeScale > 0) {
    while (G3.queue.length && G3.queue[0].row[0] <= play && spawned < 90) {
      const {row, str} = G3.queue.shift();
      if (play - row[0] < 8000 * Math.max(1, G3.speed)) { spawn(row, str, at); spawned++; }
    }
  }
  if (G3.queue.length > 20000) G3.queue.splice(0, G3.queue.length - 20000);
  const {pos, col, size, alpha} = P, cTmp = new THREE.Color();
  let alertHit = 0;
  const selI = G3.sel && G3.sel.i;
  for (let i = 0; i < P.n; i++) {
    const k = P.k[i], h = i * 3;
    if (k < 0) { size[h] = size[h + 1] = size[h + 2] = 0; continue; }
    const p = (at - P.t0[i]) / P.dur[i];
    if (p >= 1) {
      const e = _a.set(P.e[i * 3], P.e[i * 3 + 1], P.e[i * 3 + 2]);
      const tg = P.target[i];
      if (k === 0) { if (tg) { tg.allow++; tg.pulse = 1; } }
      else {
        burst(e, KIND[k].col, k === 6);
        if (tg && tg.beacon) G3.beaconHits = 1;
        else if (tg) { tg.block = (tg.block || 0) + 1; tg.hits = (tg.hits || 0) + 1; tg.pulse = 1; tg.last = performance.now(); }
        if (k >= 5 || k === 2) alertHit = 1;
      }
      if (selI === i) { G3.sel.landed = e.clone(); G3.sel.i = null; }
      P.k[i] = -1; P.free.push(i);
      size[h] = size[h + 1] = size[h + 2] = 0;
      continue;
    }
    cTmp.setHex(KIND[k].col);
    const dim = G3.focusKind !== null && G3.focusKind !== k ? 0.12 : 1;
    for (let s = 0; s < 3; s++) {
      const q = Math.max(0, p - s * 0.035), u = 1 - q, j = (h + s) * 3;
      for (let ax = 0; ax < 3; ax++) pos[j + ax] = u * u * P.s[i * 3 + ax] + 2 * u * q * P.c[i * 3 + ax] + q * q * P.e[i * 3 + ax];
      col[j] = cTmp.r; col[j + 1] = cTmp.g; col[j + 2] = cTmp.b;
      size[h + s] = (k === 6 ? 7 : k === 0 ? 3.2 : 2.7) * (1 - s * 0.3) * (i === selI ? 2.2 : 1);
      alpha[h + s] = Math.min(1, p * 6) * (1 - s * 0.38) * dim;
    }
  }
  while (P.n > 0 && P.k[P.n - 1] < 0) P.n--;
  for (const a of ['position', 'pcolor', 'psize', 'palpha']) P.geo.attributes[a].needsUpdate = true;
  P.geo.setDrawRange(0, P.n * 3);
  for (const b of G3.bursts) {
    if (!b.m.visible) continue;
    const kk = (at - b.t0) / b.dur;
    if (kk >= 1) { b.m.visible = false; continue; }
    const s = (b.big ? 6 : 2.2) * (0.4 + kk * 1.6);
    b.m.scale.set(s, s, s); b.m.material.opacity = (1 - kk) * (b.big ? 1 : 0.85);
  }
  // selection ring follows the captured request
  if (G3.sel) {
    const r = G3.selRing;
    if (G3.sel.i !== null && G3.sel.i !== undefined && P.k[G3.sel.i] >= 0) { r.visible = true; r.position.set(pos[G3.sel.i * 9], pos[G3.sel.i * 9 + 1], pos[G3.sel.i * 9 + 2]); }
    else if (G3.sel.landed) { r.visible = true; r.position.copy(G3.sel.landed); }
    else r.visible = false;
    r.lookAt(G3.camera.position);
    r.scale.setScalar(1 + 0.15 * Math.sin(now / 180));
  } else G3.selRing.visible = false;
  const t = now / 1000;
  G3.alert = Math.max(alertHit, (G3.alert || 0) - dt / 1600);
  G3.fres.uniforms.uAlert.value = G3.alert * 0.6;
  G3.fres.uniforms.uPulse.value = 0.08 * Math.sin(t * 1.7) + 0.08;
  if (G3.timeScale > 0) { G3.rings.rotation.y = t * 0.06; G3.shell.rotation.y = -t * 0.025; G3.core.rotation.set(t * 0.4, t * 0.6, 0); }
  G3.coreGlow.scale.setScalar(1 + 0.25 * Math.sin(t * (2 + Math.min(G3.eps || 0, 400) / 60)));
  G3.beaconHits = Math.max(0, G3.beaconHits - dt / 400);
  G3.beacon.rotation.y = t; G3.beacon.scale.setScalar(1 + G3.beaconHits * 0.6);
  for (const o of Object.values(G3.orbs)) {
    o.pulse = Math.max(0, o.pulse - dt / 500);
    const tot = o.allow + o.block, ratio = tot ? o.block / tot : 0;
    o.mesh.material.color.setRGB(0.3 + 0.7 * ratio, 0.64 * (1 - ratio) + 0.3 * ratio, 1 - 0.7 * ratio);
    const scale = 0.7 + Math.min(1.8, Math.log10(1 + (o.live || 0)) * 0.55) + o.pulse * 0.5;
    o.mesh.scale.setScalar(scale); o.halo.scale.setScalar(scale); o.halo.lookAt(G3.camera.position);
  }
  for (const d of Object.values(G3.doors)) {
    d.pulse = Math.max(0, d.pulse - dt / 350);
    const s = 0.8 + Math.min(1.6, Math.log10(1 + (d.live || 0)) * 0.45) + d.pulse * 0.4;
    d.mesh.scale.setScalar(s); d.gate.scale.setScalar(s);
    d.mesh.material.opacity = 0.55 + d.pulse * 0.45;
  }
  G3.controls.autoRotate = G3.autoRotate && G3.timeScale > 0;
  G3.controls.update();
  G3.composer.render();
  if (now - (G3.lblT || 0) > 60) { placeLabels(); G3.lblT = now; }
  if (now - (G3.headT || 0) > (G3.mode === 'replay' ? 250 : 1000)) { moveHead(); G3.headT = now; }
  if (now - (G3.feedT || 0) > 300) { drawFeed(); G3.feedT = now; }
}

function placeLabels() {
  const cam = G3.camera, W = G3.canvas.clientWidth, H = G3.canvas.clientHeight;
  const show = (el, p, dy) => {
    const v = _b.copy(p).project(cam);
    if (v.z > 1 || !G3.labels) { el.style.display = 'none'; return; }
    el.style.display = '';
    el.style.transform = `translate(${(v.x * .5 + .5) * W}px, ${(-v.y * .5 + .5) * H + (dy || 0)}px)`;
  };
  const top = new Set(Object.values(G3.orbs).filter(o => o.live).sort((a, b) => b.live - a.live).slice(0, 10));
  for (const o of Object.values(G3.orbs)) {
    const live = o.live || 0;
    o.el.querySelector('.n').textContent = live ? ` ${fmtK(live)}` : '';
    o.el.classList.toggle('hot', (o.liveBlock || 0) > live * 0.3 && (o.liveBlock || 0) > 3);
    if (!top.has(o) && G3.focus !== o) { o.el.style.display = 'none'; continue; }
    show(o.el, o.pos, -18);
  }
  const topDoors = new Set(Object.values(G3.doors).sort((a, b) => (b.live || 0) - (a.live || 0)).slice(0, 8));
  for (const d of Object.values(G3.doors)) {
    d.el.querySelector('.n').textContent = d.live ? fmtK(d.live) : '';
    if (!topDoors.has(d)) { d.el.style.display = 'none'; continue; }
    show(d.el, d.pos, -22);
  }
  if (G3.fwLabel) show(G3.fwLabel, _c.set(0, -RF - 4, 0), 0);
  if (G3.beaconLabel) { G3.beaconLabel.querySelector('.n').textContent = G3.fwLive ? fmtK(G3.fwLive) + ' denied' : ''; show(G3.beaconLabel, G3.beaconPos, -26); }
  if (G3.ringLabel) show(G3.ringLabel, _c.set(RD + 2, 0, 0), 10);
  for (const d of Object.values(G3.countryDots)) show(d.el, d.pos, -14);
}

// ------------------------------------------------------------------ request capture
function reasonHTML(row, str) {
  const [t, ci, dpt, v, ai, src, attack, si, pid, why] = row;
  const k = kindOf(v, why), svc = g3PortName(dpt), country = str.countries[ci] || 'unknown country';
  const server = str.servers[si];
  const rules = (g3Svc(dpt) || {}).rules || [];
  if (k === 0) return `Allowed by rule <b>${esc(g3Rule(pid))}</b> and delivered to <b>${esc(svc)}</b>${server ? ` on ${esc(server)}` : ''}.`;
  if (k === 1) return `<b>Denied - port ${esc(dpt)} (${esc(svc)}) is closed.</b> No firewall rule opens this port, so the default deny dropped it before it reached anything. This is what internet scanning looks like.`;
  if (k === 2) return `<b>Denied - port ${esc(dpt)} is open, but not for this source.</b>
    ${rules.length ? `${rules.length} rule${rules.length === 1 ? '' : 's'} open port ${esc(dpt)} (e.g. ${rules.slice(0, 2).map(r => `#${r.id} “${esc(r.name || '')}” - ${esc(r.source)}`).join('; ')}${rules.length > 2 ? ` +${rules.length - 2} more` : ''}),` : 'Rules open this port,'}
    but none of them lets ${esc(src)} (${esc(country)}) reach ${esc(server || 'this server')}, so the default deny dropped it.`;
  if (k === 3) return `<b>Denied by deny rule ${esc(g3Rule(pid))}.</b> An explicit block rule (e.g. attacker list or blocked countries) matched this request.`;
  if (k === 4) return `<b>Denied - it targeted the firewall itself</b> (port ${esc(dpt)}${svc && !svc.startsWith('port') ? ` · ${esc(svc)}` : ''}). No local-in policy allows this, so the FortiGate refused it.`;
  if (k === 5) return `<b>Blocked by a security profile</b> on rule ${esc(g3Rule(pid))}: the port was allowed, but application control / IPS stopped ${esc(str.apps[ai] || 'the session')}.`;
  return `<b>IPS threat:</b> signature “${esc(attack)}” matched on rule ${esc(g3Rule(pid))}.`;
}
function previewHTML(row, str) {
  const [t, ci, dpt, v, ai, src, attack, si, pid, why, fid, off, spt] = row, k = kindOf(v, why);
  return `<div class="hk" style="color:${KIND[k].css}">● ${esc(KIND[k].name)}</div>
    <div class="mono">${esc(src || '?')}${spt ? ':' + spt : ''} <span class="muted">${esc(str.countries[ci] || '')}</span></div>
    <div>→ :${esc(dpt)} ${esc(g3PortName(dpt))}</div><div class="muted">${esc(fmtT(t).slice(11))}.${String(t % 1000).padStart(3, '0')} · click to capture</div>`;
}
async function selectRequest(row, str, particleIndex) {
  const [t, ci, dpt, v, ai, src, attack, si, pid, why, fid, off, spt] = row, k = kindOf(v, why);
  G3.sel = {row, i: particleIndex !== undefined && particleIndex !== null && G3.P.k[particleIndex] >= 0 ? particleIndex : null, landed: null};
  const ref = fid !== null && fid !== undefined ? `${fid}:${off}:${t}` : null;
  const box = $('#g3-req');
  box.hidden = false;
  const ms = `${fmtT(t)}.${String(t % 1000).padStart(3, '0')} ${S.tz.toUpperCase()}`;
  box.innerHTML = `<button class="x" id="g3-req-x">✕</button>
    <div class="rq-h" style="--k:${KIND[k].css}"><span class="rq-v">${KIND[k].short}</span><div><b>Captured request</b><div class="muted mono">${esc(ms)}</div></div></div>
    <div class="rq-reason">${reasonHTML(row, str)}</div>
    <div class="rq-path"><span class="mono">${esc(src || '?')}${spt ? ':' + spt : ''}</span><i>${esc(str.countries[ci] || '')}</i>
      <span class="arr" style="color:${KIND[k].css}">➜</span><span>${esc(((S.meta || {}).firewall || {}).name || 'FortiGate')}</span><span class="arr" style="color:${KIND[k].css}">${v === 0 ? '➜' : '✕'}</span>
      <span>:${esc(dpt)} ${esc(g3PortName(dpt))}</span></div>
    <table class="kvt">
      <tr><td>Source</td><td class="mono">${esc(src || 'not recorded')}${spt ? ':' + spt : ''} · ${esc(str.countries[ci] || '')}</td></tr>
      <tr><td>Destination</td><td class="mono">${esc(str.servers[si] || '')} :${esc(dpt)}</td></tr>
      <tr><td>Service</td><td>${esc(g3PortName(dpt))}</td></tr>
      <tr><td>Application</td><td>${appH(str.apps[ai] || '') || '<span class="na">not identified</span>'}</td></tr>
      <tr><td>Rule</td><td>${pid === null || pid === undefined ? '<span class="na">none</span>' : esc(g3Rule(pid))}</td></tr>
      <tr><td>Decision</td><td style="color:${KIND[k].css}">${esc(KIND[k].name)}</td></tr>
      <tr><td>Log reference</td><td class="mono">${ref ? esc(ref) : '<span class="na">reconstructed from summaries - no single log line</span>'}</td></tr>
    </table>
    <div id="g3-req-raw" class="rq-raw">${ref ? '<div class="muted">loading the original FortiGate log…</div>' : ''}</div>
    <div class="rq-btns">${ref ? `<a class="btn-primary rq-b" href="#investigate?q=${encodeURIComponent(src)}&ref=${encodeURIComponent(ref)}">🔍 Investigate this request</a>` : ''}
      ${src ? `<a class="rq-b" href="#investigate?trace=ip:${encodeURIComponent(src)}">Trace ${esc(src)}</a>` : ''}
      <button class="rq-b" id="g3-req-follow">${G3.timeScale ? '❄ Freeze scene' : '▶ Resume'}</button></div>`;
  $('#g3-req-x').onclick = () => { box.hidden = true; G3.sel = null; };
  $('#g3-req-follow').onclick = () => setTimeScale(G3.timeScale ? 0 : 1);
  if (!ref) return;
  try {
    const r = await api('/api/inv/raw', {ref});
    if (!G3.sel || G3.sel.row !== row) return;
    const f = r.fields || {};
    const pick = [['Session ID', f.externalId], ['Action', f.act], ['Log type', f.cat], ['Policy type', f.FTNTFGTpolicytype],
      ['Public destination', f.dst], ['Translated to (NAT)', f.destinationTranslatedAddress && `${f.destinationTranslatedAddress}:${f.destinationTranslatedPort || ''}`],
      ['Ingress → egress', `${f.deviceInboundInterface || '?'} → ${f.deviceOutboundInterface || '?'}`],
      ['Client reputation', f.FTNTFGTcrlevel && `${f.FTNTFGTcrlevel} (score ${f.FTNTFGTcrscore})`], ['Internet service', f.FTNTFGTsrcinetsvc],
      ['Bytes sent / received', (f.out || f.in) && `${f.out || 0} / ${f.in || 0}`], ['Duration (s)', f.FTNTFGTduration], ['Log ID', f.FTNTFGTlogid]]
      .filter(([, x]) => x !== undefined && x !== null && x !== '' && x !== '? → ?');
    $('#g3-req-raw').innerHTML = `<table class="kvt">${pick.map(([kk, x]) => `<tr><td>${esc(kk)}</td><td class="mono">${esc(x)}</td></tr>`).join('')}</table>
      <details><summary>Original FortiGate log (${Object.keys(f).length} fields)</summary><pre>${esc(r.raw || JSON.stringify(f, null, 1))}</pre></details>`;
  } catch (e) { $('#g3-req-raw').innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
function drawFeed() {
  const box = $('#g3-feed');
  if (!box || box.matches(':hover')) return;                  // don't move rows under the cursor
  const seen = G3.feedSeen || 0;
  G3.feedSeen = G3.feed.length ? G3.feed[0].seq : seen;
  box.innerHTML = G3.feed.slice(0, 40).map((f, idx) => {
    const [t, ci, dpt, v, ai, src, attack, si, pid, why, fid, off, spt] = f.row, k = kindOf(v, why);
    if (!G3.show[k]) return '';
    return `<div class="fr${f.seq > seen ? ' new' : ''}" data-i="${idx}" style="--k:${KIND[k].css}"><span class="mono t">${esc(fmtT(t).slice(11))}.${String(t % 1000).padStart(3, '0')}</span>
      <span class="mono s">${esc(src || '·')}</span><span class="c">${esc((f.str.countries[ci] || '').slice(0, 12))}</span>
      <span class="p">:${esc(dpt)} ${esc(g3PortName(dpt).replace(/\s*\(.*\)/, '').slice(0, 14))}</span><span class="v">${KIND[k].short}</span></div>`;
  }).join('') || '<div class="muted">waiting for requests…</div>';
  box.querySelectorAll('.fr').forEach(el => el.onclick = () => {
    const f = G3.feed[+el.dataset.i];
    selectRequest(f.row, f.str, f.i !== undefined && G3.P.ev[f.i] && G3.P.ev[f.i].seq === f.seq ? f.i : null);
  });
}
function setTimeScale(s) {
  G3.timeScale = s;
  const fb = $('#g3-freeze'), sb = $('#g3-slow'), fl = $('#g3-req-follow');
  if (fb) { fb.classList.toggle('on', s === 0); fb.textContent = s === 0 ? '▶ Resume' : '❄ Freeze'; }
  if (sb) sb.classList.toggle('on', s > 0 && s < 1);
  if (fl) fl.textContent = s ? '❄ Freeze scene' : '▶ Resume';
  $('#g3').classList.toggle('frozen', s === 0);
  if (s === 0) toast('Scene frozen - hover and click any particle to capture that request', 'info');
}

// ------------------------------------------------------------------ data feeds
function stopFeeds() {
  clearTimeout(G3.liveTimer); G3.liveTimer = null;
  clearTimeout(G3.replayTimer); G3.replayTimer = null;
}
function enqueue(res) {
  const str = res.events;
  for (const row of str.rows) G3.queue.push({row, str});
  G3.queue.sort((a, b) => a.row[0] - b.row[0]);
  G3.fired += (res.new || []).reduce((a, b) => a + b, 0);
  applyAgg(res.agg, res);
}
function startLive() {
  stopFeeds();
  G3.mode = 'live'; G3.queue = []; G3.since = 0;
  setModeUI();
  const tick = async () => {
    if (!G3.canvas || !G3.canvas.isConnected || G3.mode !== 'live') return;
    try {
      const r = await api('/api/graph3d/live', {since: G3.since});
      if (G3.mode !== 'live') return;
      const target = Date.now() - r.newest + 3500;
      G3.lag = G3.lag ? G3.lag * 0.8 + target * 0.2 : target;
      if (!G3.since) r.new = [0, 0, 0, 0];                     // the first batch is history, not newly fired
      G3.since = r.newest; G3.eps = r.eps;
      enqueue(r);
      $('#g3-sub').textContent = `every particle is a real log line · ${r.deny_sample > 1 ? 'scanner particles sampled 1:' + r.deny_sample : 'nothing sampled'} · panels = last ${r.window_ms / 1000}s`;
    } catch (e) { $('#g3-sub').textContent = 'live feed error: ' + e.message; }
    G3.liveTimer = setTimeout(tick, 2000);
  };
  tick();
}
function startReplay(t) {
  stopFeeds();
  const sp = G3.sp;
  G3.mode = 'replay'; G3.queue = []; G3.playTime = Math.max(sp.frm, Math.min(t, Date.now() - 5000));
  G3.fetched = G3.playTime; G3.playing = true;
  setModeUI();
  const tick = async () => {
    if (!G3.canvas || !G3.canvas.isConnected || G3.mode !== 'replay') return;
    const winLen = Math.min(120_000, Math.max(30_000, 4000 * G3.speed));
    if (G3.fetched < G3.playTime + winLen * 0.6 && !G3.busy) {
      const frm = Math.max(G3.fetched, G3.playTime - 2000);
      G3.busy = true;
      try {
        const r = await api('/api/graph3d/events', {frm: Math.round(frm), to: Math.round(frm + winLen)});
        if (G3.mode === 'replay') {
          enqueue(r);
          G3.fetched = r.to;
          $('#g3-sub').textContent = r.mode === 'raw' ? `exact replay of real log lines · ${r.deny_sample > 1 ? 'scanner particles sampled 1:' + r.deny_sample : 'nothing sampled'}`
            : 'reconstructed replay (raw logs archived) - counts from 5-minute / hourly summaries, particles are representative';
        }
      } catch (e) { $('#g3-sub').textContent = 'replay error: ' + e.message; }
      G3.busy = false;
    }
    if (G3.playTime >= Date.now() - 6000) { startLive(); return; }
    G3.replayTimer = setTimeout(tick, 400);
  };
  tick();
}

function applyAgg(agg, res) {
  const tt = agg.totals;
  animateNum('#g3-n0', tt.allowed); animateNum('#g3-n1', tt.denied); animateNum('#g3-n2', tt.blocked); animateNum('#g3-n3', tt.threats);
  G3.portTitles = Object.assign(G3.portTitles || {}, Object.fromEntries(agg.ports.map(p => [p.port, p.title])),
    Object.fromEntries((agg.closed_ports || []).map(p => [p.port, p.title])));
  // requests per second + sparkline
  const rate = agg.rate || [];
  const last = rate.slice(-6, -1);                            // the newest second is still filling up
  const rps = last.length ? last.reduce((a, r) => a + r[1] + r[2] + r[3] + r[4], 0) / last.length : 0;
  animateNum('#g3-rps', Math.round(rps));
  $('#g3-fired').textContent = `${fmtN(G3.fired)} requests fired since you opened this view`;
  drawSpark(rate.slice(-60));
  const bars = (rows, allowK, blockK, labelFn, clickable) => {
    const max = Math.max(1, ...rows.map(r => (r[allowK] || 0) + (r[blockK] || 0)));
    return rows.slice(0, 8).map((r, i) => {
      const a = r[allowK] || 0, b = r[blockK] || 0;
      return `<div class="g3-bar" ${clickable ? `data-i="${i}"` : ''}><div class="l">${labelFn(r)}</div><div class="v">${fmtK(a + b)}</div>
        <div class="track"><i class="a" style="width:${100 * a / max}%"></i><i class="b" style="width:${100 * b / max}%"></i></div></div>`;
    }).join('') || '<div class="muted">—</div>';
  };
  const ports = agg.ports.map(p => Object.assign({}, p, {bad: p.denied + p.blocked + p.threats}));
  $('#g3-ports').innerHTML = bars(ports, 'allowed', 'bad', r => `<b>:${esc(r.port)}</b> <span class="muted">${esc((r.title || '').replace(/\s*\(.*\)/, '').slice(0, 20))}</span>${r.exposed ? ' <span class="tag">open</span>' : ''}`, true);
  $('#g3-ports').querySelectorAll('[data-i]').forEach(el => el.onclick = () => { const p = ports[+el.dataset.i]; G3.orbs[p.port] ? showOrb(p.port) : showDoor(p.port); });
  $('#g3-apps').innerHTML = bars(agg.apps, 'allowed', 'blocked', r => esc(r.app));
  $('#g3-ctry').innerHTML = bars(agg.countries, 'allowed', 'blocked', r => esc(r.country));
  $('#g3-att').innerHTML = agg.attackers.slice(0, 7).map(a => `<a class="g3-att" href="#investigate?trace=ip:${encodeURIComponent(a.src)}">
    <span class="mono">${esc(a.src)}</span><b>${fmtK(a.n)}</b><span class="muted">${esc(a.country)} · ${a.ports} port${a.ports === 1 ? '' : 's'}</span>
    <span class="muted" style="text-align:right">${a.why ? esc(KIND[a.why].name.replace('Denied · ', '')) : ''}</span></a>`).join('') || '<div class="muted">none</div>';
  $('#g3-thr').innerHTML = agg.threats.map(x => `<div class="g3-thr">☣ <b>${esc(x.attack)}</b><span class="muted"> ${esc(x.src)} → :${esc(x.port)} ×${x.n}</span></div>`).join('') || '<div class="muted">no IPS events in this window</div>';
  // why denied
  const whyTotal = Math.max(1, (agg.why || []).reduce((a, w) => a + w.n, 0));
  $('#g3-why').innerHTML = [1, 2, 3, 4].map(k => {
    const w = (agg.why || []).find(x => x.why === k) || {n: 0, ports: []};
    return `<div class="wy ${G3.focusKind === k ? 'on' : ''}" data-k="${k}" title="${esc(KIND[k].tip)}" style="--k:${KIND[k].css}">
      <div class="wl"><i></i>${esc(KIND[k].name.replace('Denied · ', ''))}<b>${fmtK(w.n)}</b><span class="muted">${Math.round(100 * w.n / whyTotal)}%</span></div>
      <div class="wt"><i style="width:${100 * w.n / whyTotal}%"></i></div>
      <div class="wp muted">${w.ports.map(p => `:${p.port} ${esc(String(p.title).replace(/\s*\(.*\)/, '').slice(0, 12))} ${fmtK(p.n)}`).join(' · ') || '—'}</div></div>`;
  }).join('') + '<div class="muted wh">Hover for what each means · click to highlight those particles</div>';
  $('#g3-why').querySelectorAll('.wy').forEach(el => el.onclick = () => { const k = +el.dataset.k; G3.focusKind = G3.focusKind === k ? null : k; el.parentNode.querySelectorAll('.wy').forEach(x => x.classList.toggle('on', +x.dataset.k === G3.focusKind)); });
  $('#g3-why-win').textContent = res.mode === 'live' ? `last ${res.window_ms / 1000}s` : '';
  // live counts on orbs, doors, beacon
  for (const o of Object.values(G3.orbs)) { o.live = 0; o.liveBlock = 0; }
  const sp = agg.svc_ports || [];
  for (const p of sp.concat(agg.ports.filter(x => !sp.some(s => s.port === x.port)))) {
    const o = G3.orbs[p.port] || (p.allowed ? G3.orbs.other : null);
    if (o) { o.live += p.allowed + p.denied + p.blocked + p.threats; o.liveBlock += p.denied + p.blocked + p.threats; }
  }
  // doors = the most-knocked closed ports; a door stays while its port is in the top 20 (no flicker), new top ports take free slots
  const closed = agg.closed_ports || [], top = closed.slice(0, DOORS - 1), rank = new Map(closed.slice(0, 20).map((p, i) => [p.port, i]));
  const dropDoor = d => { G3.scene.remove(d.mesh, d.gate); d.el.remove(); delete G3.doors[d.port]; };
  for (const d of Object.values(G3.doors)) { d.live = 0; if (d.port !== 'other' && !rank.has(d.port)) dropDoor(d); }
  const other = door('other', 'other closed ports');
  const need = top.filter(p => !G3.doors[p.port]);
  const spare = Object.values(G3.doors).filter(d => d.port !== 'other' && !top.some(p => p.port === d.port)).sort((a, b) => rank.get(b.port) - rank.get(a.port));
  while (need.length > DOORS - Object.keys(G3.doors).length && spare.length) dropDoor(spare.shift());
  for (const p of closed.slice(0, 20)) { const d = G3.doors[p.port] || (top.includes(p) ? door(p.port, p.title) : null); if (d) d.live = p.n; }
  const inDoors = closed.filter(p => G3.doors[p.port]).reduce((a, p) => a + p.n, 0);
  other.live = Math.max(0, (((agg.why || []).find(w => w.why === 1) || {}).n || 0) - inDoors);
  G3.fwLive = ((agg.why || []).find(w => w.why === 4) || {}).n || 0;
  // country markers
  const keep = new Set();
  agg.countries.slice(0, 10).forEach(c => {
    if (!c.country || c.country === '?') return;
    keep.add(c.country);
    let d = G3.countryDots[c.country];
    if (!d) {
      const pos = countryVec(c.country, RS);
      const mesh = new THREE.Mesh(new THREE.SphereGeometry(1.1, 12, 12), new THREE.MeshBasicMaterial({color: 0xffffff, transparent: true, opacity: 0.9}));
      mesh.position.copy(pos); G3.scene.add(mesh);
      d = G3.countryDots[c.country] = {pos, mesh, el: g3Label('', 'ctry')};
    }
    const bad = c.blocked / Math.max(1, c.allowed + c.blocked);
    d.mesh.material.color.setRGB(0.3 + 0.7 * bad, 0.64 * (1 - bad) + 0.25, 1 - 0.75 * bad);
    d.mesh.scale.setScalar(0.8 + Math.log10(1 + c.allowed + c.blocked) * 0.5);
    d.el.innerHTML = `${esc(c.country)} <b>${fmtK(c.allowed + c.blocked)}</b>`;
  });
  for (const [name, d] of Object.entries(G3.countryDots)) if (!keep.has(name)) { G3.scene.remove(d.mesh); d.el.remove(); delete G3.countryDots[name]; }
  $('#g3-thr-sec h4').textContent = `IPS threats · ${res.mode === 'live' ? `last ${res.window_ms / 1000}s` : fmtT(res.frm).slice(11) + ' → ' + fmtT(res.to).slice(11)}`;
}
function drawSpark(rate) {
  const cv = $('#g3-spark'); if (!cv) return;
  const W = cv.clientWidth, H = cv.clientHeight, dpr = Math.min(devicePixelRatio, 2);
  cv.width = W * dpr; cv.height = H * dpr;
  const ctx = cv.getContext('2d'); ctx.scale(dpr, dpr);
  const max = Math.max(1, ...rate.map(r => r[1] + r[2] + r[3] + r[4]));
  const bw = W / 60;
  rate.forEach((r, i) => {
    const x = W - (rate.length - i) * bw;
    const hA = (H - 2) * r[1] / max, hD = (H - 2) * r[2] / max, hO = (H - 2) * (r[3] + r[4]) / max;
    ctx.fillStyle = '#4da3ff'; ctx.fillRect(x, H - hA, bw - 1, hA);
    ctx.fillStyle = 'rgba(255,77,77,.85)'; ctx.fillRect(x, H - hA - hD, bw - 1, hD);
    ctx.fillStyle = '#ffd24d'; ctx.fillRect(x, H - hA - hD - hO, bw - 1, hO);
  });
  ctx.fillStyle = 'rgba(255,255,255,.35)'; ctx.font = '9px system-ui'; ctx.fillText(`peak ${max}/s · last 60 s`, 4, 10);
}
function animateNum(sel, target) {
  const el = $(sel); if (!el) return;
  const from = +(el.dataset.v || 0), t0 = performance.now();
  el.dataset.v = target;
  const step = now => { const kk = Math.min(1, (now - t0) / 700); el.textContent = fmtK(Math.round(from + (target - from) * (1 - Math.pow(1 - kk, 3)))); if (kk < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}

function flyTo(pos, dist) {
  const target = pos.clone().normalize().multiplyScalar(dist).add(new THREE.Vector3(0, 12, 0));
  const from = G3.camera.position.clone(), t0 = performance.now();
  G3.autoRotate = false; const rot = $('#g3-rot'); if (rot) rot.checked = false;
  const fly = now => { const kk = Math.min(1, (now - t0) / 900), e = 1 - Math.pow(1 - kk, 3); G3.camera.position.lerpVectors(from, target, e); if (kk < 1) requestAnimationFrame(fly); };
  requestAnimationFrame(fly);
}
function showOrb(port) {
  const o = G3.orbs[port]; if (!o) return;
  G3.focus = o;
  const s = o.svc, box = $('#g3-req');
  box.hidden = false;
  box.innerHTML = `<button class="x" id="g3-req-x">✕</button><h4 style="margin:0 0 6px">:${esc(s.port)} ${esc(s.title)} <span class="tag">open service</span></h4>
    ${s.level && s.level !== 'none' ? `<div>${lvPill(s.level, s.score)} <span class="muted">who can reach it: ${esc(s.scope || '')}</span></div>` : ''}
    <div class="muted" style="margin:6px 0">Current window: <b>${fmtN(o.live || 0)}</b> requests, <b class="drop">${fmtN(o.liveBlock || 0)}</b> denied / blocked</div>
    ${(s.rules || []).length ? `<div class="fk">Opened by rules</div>${s.rules.map(r => `<div><a href="#security?tab=rules" data-rule="${r.id}">#${r.id} ${esc(r.name || '')}</a> <span class="muted">${esc(r.source || '')}</span></div>`).join('')}` : ''}
    <div class="rq-btns"><a class="rq-b" href="#investigate?q=port+${encodeURIComponent(s.port)}">Investigate this port →</a></div>`;
  $('#g3-req-x').onclick = () => { box.hidden = true; G3.focus = null; };
  box.querySelectorAll('[data-rule]').forEach(a => a.onclick = e => { e.preventDefault(); g3Fullscreen(false); openRule(+a.dataset.rule); });
  flyTo(o.pos, 70);
}
function showDoor(port) {
  const d = G3.doors[port]; if (!d) return;
  const box = $('#g3-req');
  box.hidden = false;
  box.innerHTML = `<button class="x" id="g3-req-x">✕</button><h4 style="margin:0 0 6px">:${esc(port)} ${esc(d.title || g3PortName(port))} <span class="tag" style="color:#ff8080">closed port</span></h4>
    <div class="rq-reason">No firewall rule opens this port, so every request to it is denied at the firewall. <b>${fmtN(d.live || 0)}</b> knocks in the current window.
      This is normal internet scanning - it only becomes a concern if you ever open this port.</div>
    <div class="rq-btns"><a class="rq-b" href="#investigate?q=port+${encodeURIComponent(port)}+denied">See who is knocking →</a></div>`;
  $('#g3-req-x').onclick = () => { box.hidden = true; };
  flyTo(d.pos, 80);
}

// ------------------------------------------------------------------ timeline
async function g3LoadTimeline(sp) {
  G3.tl = await api('/api/graph3d/timeline', sp);
  g3DrawTimeline();
}
function g3DrawTimeline() {
  const tl = G3.tl, cv = $('#g3-tl');
  if (!tl || !cv) return;
  const W = cv.clientWidth, H = cv.clientHeight, dpr = Math.min(devicePixelRatio, 2);
  cv.width = W * dpr; cv.height = H * dpr;
  const ctx = cv.getContext('2d');
  ctx.scale(dpr, dpr);
  const b = tl.buckets, n = b.length || 1, bw = W / n;
  const tot = r => r[1] + r[2] + r[3];
  const max = Math.sqrt(Math.max(1, ...b.map(tot)));
  const y = v => (H - 14) * Math.sqrt(v) / max;
  b.forEach((r, i) => {
    // stacked: allowed (blue), denied by the firewall (red), stopped by a security profile (yellow)
    const x = i * bw, w = Math.max(1, bw - .5), hA = y(r[1]), hAD = y(r[1] + r[2]), hAll = y(tot(r));
    ctx.fillStyle = 'rgba(77,163,255,.85)'; ctx.fillRect(x, H - hA, w, hA);
    ctx.fillStyle = 'rgba(255,77,77,.6)'; ctx.fillRect(x, H - hAD, w, hAD - hA);
    ctx.fillStyle = 'rgba(255,210,77,.9)'; ctx.fillRect(x, H - hAll, w, hAll - hAD);
  });
  G3.markerX = [];
  (tl.markers || []).forEach(m => {
    const x = (m.t - tl.frm) / (tl.to - tl.frm) * W;
    ctx.fillStyle = m.type === 'threat' ? '#9d7bff' : '#fcc34d';
    ctx.beginPath(); ctx.moveTo(x, 1); ctx.lineTo(x - 4, 9); ctx.lineTo(x + 4, 9); ctx.fill();
    G3.markerX.push([x, m]);
  });
  const track = $('#g3-track');
  track.onmousemove = e => {
    const r = track.getBoundingClientRect(), x = e.clientX - r.left, row = b[Math.floor(x / bw)], tip = $('#g3-tip');
    if (!row) return;
    const mk = G3.markerX.filter(([mx]) => Math.abs(mx - x) < 5).map(([, m]) => `<div class="mk ${m.type}">${m.type === 'threat' ? '☣' : '🔑'} ${esc(m.label)}</div>`).join('');
    tip.hidden = false;
    tip.style.left = Math.min(W - 250, Math.max(0, x - 110)) + 'px';
    tip.innerHTML = `<b>${esc(fmtT(row[0], 'dhm'))}</b><div><i class="dot a"></i>${fmtN(row[1])} allowed</div><div><i class="dot d"></i>${fmtN(row[2])} denied</div>
      ${row[3] ? `<div><i class="dot u"></i>${fmtN(row[3])} security blocks</div>` : ''}${row[4] ? `<div><i class="dot t"></i>${row[4]} IPS threats</div>` : ''}${mk}
      <div class="muted">click to replay from here</div>`;
  };
  track.onmouseleave = () => { $('#g3-tip').hidden = true; };
  track.onclick = e => { const r = track.getBoundingClientRect(); startReplay(tl.frm + (e.clientX - r.left) / W * (tl.to - tl.frm)); };
  moveHead();
}
function moveHead() {
  const tl = G3.tl, head = $('#g3-head'), cv = $('#g3-tl');
  if (!tl || !head || !cv) return;
  const t = G3.mode === 'live' ? Date.now() : G3.playTime;
  const x = (t - tl.frm) / (tl.to - tl.frm) * cv.clientWidth;
  head.style.transform = `translateX(${Math.max(0, Math.min(cv.clientWidth, x))}px)`;
  head.classList.toggle('live', G3.mode === 'live');
  $('#g3-clock').textContent = fmtT(t).slice(5) + ' ' + S.tz.toUpperCase();
  $('#g3-tlabel').textContent = G3.mode === 'live' ? 'watching live traffic' : `replaying ${fmtT(t, 'dhm')} at ${G3.speed}×`;
}
function setModeUI() {
  const live = G3.mode === 'live';
  $('#g3-mode').textContent = live ? 'LIVE' : 'REPLAY';
  $('#g3').classList.toggle('replay', !live);
  $('#g3-live').classList.toggle('on', live);
  $('#g3-play').textContent = G3.playing || live ? '⏸' : '▶';
  $('#g3-note').textContent = live ? 'Hover a particle · click to capture · click the timeline to replay' : 'Exact log lines where raw logs exist; older periods are reconstructed';
  moveHead();
}
// Full screen: the browser Fullscreen API on the graph element; if the browser refuses (e.g. embedded frame), fill the window instead
const g3IsFull = el => document.fullscreenElement === el || el.classList.contains('max');
function g3Fullscreen(on) {
  const el = $('#g3');
  if (!el) return;
  if (on === undefined) on = !g3IsFull(el);
  if (on === g3IsFull(el)) return;
  if (on) {
    const fallback = () => { el.classList.add('max'); g3FsUI(); };
    if (el.requestFullscreen) el.requestFullscreen({navigationUI: 'hide'}).catch(fallback); else fallback();
  } else {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    el.classList.remove('max');
    g3FsUI();
  }
}
function g3FsUI() {
  const el = $('#g3'), b = $('#g3-fs');
  if (!el || !b) return;
  const on = g3IsFull(el);
  b.classList.toggle('on', on);
  b.textContent = on ? '✕ Exit full screen' : '⛶ Full screen';
}
function bindControls() {
  $('#g3-live').onclick = () => startLive();
  $('#g3-play').onclick = () => {
    if (G3.mode === 'live') { startReplay(Date.now() - 120_000); G3.playing = false; }
    else G3.playing = !G3.playing;
    setModeUI();
  };
  const jump = d => startReplay((G3.mode === 'live' ? Date.now() - 60_000 : G3.playTime) + d);
  $('#g3-back').onclick = () => jump(-60_000);
  $('#g3-fwd').onclick = () => jump(60_000);
  $('#g3-speed').onclick = e => {
    const b = e.target.closest('button'); if (!b) return;
    G3.speed = +b.dataset.s;
    $('#g3-speed').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
    if (G3.mode === 'live' && G3.speed > 1) startReplay(Date.now() - 30 * 60_000);
    setModeUI();
  };
  $('#g3-freeze').onclick = () => setTimeScale(G3.timeScale === 0 ? 1 : 0);
  $('#g3-slow').onclick = () => setTimeScale(G3.timeScale > 0 && G3.timeScale < 1 ? 1 : 0.2);
  $('#g3-next').onclick = () => {
    const t = G3.mode === 'live' ? G3.sp.frm : G3.playTime + 1000;
    const m = (G3.tl.markers || []).find(x => x.t > t) || (G3.tl.markers || [])[0];
    if (m) { startReplay(m.t - 20_000); toast(`${m.type === 'threat' ? '☣' : '🔑'} ${m.label}`, m.type === 'threat' ? 'threat' : 'brute'); }
    else toast('No attack markers in this range', 'info');
  };
  document.querySelectorAll('.g3-legend [data-k]').forEach(cb => cb.onchange = () => { G3.show[+cb.dataset.k] = cb.checked; });
  $('#g3-rot').onchange = e => { G3.autoRotate = e.target.checked; };
  $('#g3-lbl').onchange = e => { G3.labels = e.target.checked; };
  $('#g3-fs').onclick = () => g3Fullscreen();
  g3FsUI();
  if (!G3.keysBound) {
    G3.keysBound = true;
    document.addEventListener('fullscreenchange', g3FsUI);
    document.addEventListener('keydown', e => {
      const t = e.target instanceof Element ? e.target : document.body;
      if (!$('#g3') || e.ctrlKey || e.metaKey || e.altKey || t.closest('input, select, textarea')) return;
      if (e.key === 'f' || e.key === 'F') { e.preventDefault(); g3Fullscreen(); }
      else if (e.key === 'Escape' && $('#g3').classList.contains('max')) g3Fullscreen(false);
      else if (e.key === ' ' && !t.closest('button, a')) { e.preventDefault(); setTimeScale(G3.timeScale === 0 ? 1 : 0); }
    });
  }
  $('#g3-reset').onclick = () => { G3.camera.position.set(0, 30, 132); G3.controls.target.set(0, 0, 0); G3.autoRotate = true; $('#g3-rot').checked = true; };
}
