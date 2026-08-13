/* ============================================================
 *  보안검사 — 커밋/업로드 전에 B등급 데이터가 섞이지 않았는지 확인한다.
 *
 *  사용법 (배포 폴더에서):
 *      node 보안검사.js
 *
 *  또는 검사.bat 을 더블클릭.
 *  하나라도 [차단] 이 나오면 절대 업로드하지 마십시오.
 * ============================================================ */
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;

/* 저장소에 올라가도 되는 파일 (화이트리스트) */
const ALLOW = new Set([
  'index.html', 'manifest.json', 'icon-192.png', 'icon-512.png',
  '.nojekyll', '.gitignore', '보안검사.js', '검사.bat'
]);

/* 내용 검사 대상 (텍스트 파일) */
const SCAN_EXT = new Set(['.html', '.json', '.js', '.css', '.md', '.txt']);

/* 규칙 설계 원칙:
 *  - [차단] 은 오탐이 사실상 없는 패턴만 넣는다. 경보가 잦으면 사람이 무시하게 되고,
 *    그때 진짜 유출이 지나간다.
 *  - 한국어 자유문에서 주소·기관명은 오탐이 많으므로 [경고] 로 두고 사람이 판단한다. */
const RULES = [
  { level:'차단', name:'Google API 키',    re:/AIza[0-9A-Za-z_\-]{30,}/ },
  { level:'차단', name:'OpenAI 형식 키',    re:/\bsk-[A-Za-z0-9]{20,}/ },
  { level:'차단', name:'Bearer 토큰',       re:/Bearer\s+[A-Za-z0-9._\-]{20,}/ },
  { level:'차단', name:'키 하드코딩',       re:/(api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["'][^"']{12,}["']/i },
  { level:'차단', name:'주민등록번호',       re:/\b\d{6}\s*[-–]\s*[1-4]\d{6}\b/ },
  { level:'차단', name:'휴대전화번호',       re:/\b01[016-9][-\s.]\d{3,4}[-\s.]\d{4}\b/ },
  { level:'차단', name:'지번 주소',         re:/[가-힣]{2,}(읍|면|동|리)\s?\d{1,4}\s?[-–]\s?\d{1,4}(?!\d)/ },
  { level:'차단', name:'백업 파일 내용',     re:/"format"\s*:\s*"fire-command-trainer-backup"/ },

  /* '~으로 30자' 같은 조사 표현이 도로명으로 오인되지 않도록 앞 음절이 '으'인 경우를 뺀다 */
  { level:'경고', name:'도로명 주소 의심',   re:/[가-힣]{2,}(대로|(?<!으)로|길)\s\d{1,4}(번길\s?\d{1,4})?(?!\d)/,
    ignore:[/고속도로/,/자동차전용도로/,/우회도로/,/진입로/,/대피로/,/퇴로/,/상황실로/,/본부로/,/병원으?로/,/현장으?로/,/기준으로/,/우선순위로/] },
  { level:'경고', name:'행정구역 + 번지',    re:/[가-힣]{2,}(시|군|구)\s+[가-힣]{2,}(읍|면|동)\s/ },
  { level:'경고', name:'대외비 표기',       re:/(대외비|내부용|한정배포|기밀)/,
    /* 앱 자체의 보안 안내 문구는 제외 — 이 문구들이 바로 사용자에게 경고하는 내용이다 */
    ignore:[/대외비·내부 자료/, /대외비 훈련용/, /대외비 내용/, /대외비 표기/,
            /대외비 자료는 전송을 켜지/, /대외비가 아님/, /대외비·내부/] },
  { level:'경고', name:'실제 소방서명 추정', re:/[가-힣]{2,}소방서/, ignore:[/○○소방서/,/□□소방서/] },
];

/* 규칙 정의 자체가 걸리므로 스캐너는 내용 검사에서 제외한다 */
const SCAN_SKIP = new Set(['보안검사.js', '검사.bat']);

let block = 0, warn = 0;
const line = '─'.repeat(58);

console.log('\n' + line);
console.log('  지휘멘트 훈련 — 업로드 전 보안 검사');
console.log(line);

/* ---------- 1. 파일 목록 검사 ---------- */
console.log('\n[1] 올라갈 파일 확인');
const files = fs.readdirSync(ROOT, { withFileTypes: true });
const uploadable = [];

/* .gitignore 가 이미 막고 있는 것들 — 존재해도 업로드되지 않으므로 차단이 아니라 안내만 한다 */
const IGNORED = [
  /\.local(\.|$)/i, /^지휘훈련_백업/, /\.backup\.json$/i,
  /\.(txt|csv|md|hwp|hwpx|pdf|xlsx|docx|log|tmp)$/i,
  /^\.env/i, /\.(key|pem)$/i, /^secrets/i,
  /\.(png|jpg|jpeg|gif|webp)$/i,
];

for (const f of files) {
  if (f.isDirectory()) {
    console.log(`  [차단] 폴더가 있습니다: ${f.name}/  → 사용자 자료 폴더일 수 있습니다`);
    block++;
    continue;
  }
  if (ALLOW.has(f.name)) {
    uploadable.push(f.name);
    console.log(`  [허용] ${f.name}`);
  } else if (IGNORED.some(re => re.test(f.name))) {
    console.log(`  [무시] ${f.name}  → .gitignore 대상, 업로드되지 않음`);
  } else {
    console.log(`  [차단] 허용 목록에 없는 파일: ${f.name}`);
    block++;
  }
}

/* ---------- 2. 내용 검사 ---------- */
console.log('\n[2] 파일 내용 검사');
for (const name of uploadable) {
  if (!SCAN_EXT.has(path.extname(name).toLowerCase())) continue;
  if (SCAN_SKIP.has(name)) { console.log(`  (건너뜀) ${name} — 검사 규칙 정의 파일`); continue; }
  const text = fs.readFileSync(path.join(ROOT, name), 'utf8');
  const lines = text.split(/\r?\n/);
  for (const rule of RULES) {
    lines.forEach((ln, i) => {
      const m = ln.match(rule.re);
      if (!m) return;
      const hit = m[0];
      if (rule.ignore && rule.ignore.some(x => x.test(ln))) return;   // 알려진 오탐 제외
      console.log(`  [${rule.level}] ${name}:${i + 1}  ${rule.name} → ${hit.slice(0, 34)}`);
      if (rule.level === '차단') block++; else warn++;
    });
  }
}
if (block === 0 && warn === 0) console.log('  민감 패턴 없음');

/* ---------- 3. 크기 급증 검사 ---------- */
console.log('\n[3] 파일 크기 확인 (데이터 하드코딩 징후)');
const SIZE_FILE = path.join(ROOT, '.size.local');
const cur = fs.existsSync(path.join(ROOT, 'index.html'))
  ? fs.statSync(path.join(ROOT, 'index.html')).size : 0;
console.log(`  index.html : ${(cur / 1024).toFixed(1)} KB`);
if (fs.existsSync(SIZE_FILE)) {
  const prev = parseInt(fs.readFileSync(SIZE_FILE, 'utf8'), 10) || 0;
  if (prev && cur > prev * 1.2) {
    console.log(`  [경고] 직전보다 ${(((cur / prev) - 1) * 100).toFixed(0)}% 커졌습니다. 데이터가 코드에 들어가지 않았는지 확인하십시오.`);
    warn++;
  }
}
try { fs.writeFileSync(SIZE_FILE, String(cur)); } catch (e) {}

/* ---------- 결과 ---------- */
console.log('\n' + line);
if (block > 0) {
  console.log(`  ❌ 차단 ${block}건, 경고 ${warn}건`);
  console.log('  업로드하지 마십시오. 위 [차단] 항목을 먼저 해결하십시오.');
} else if (warn > 0) {
  console.log(`  ⚠️  경고 ${warn}건 — 내용을 확인한 뒤 판단하십시오.`);
} else {
  console.log('  ✅ 통과 — 업로드해도 안전합니다.');
}
console.log(line + '\n');

process.exit(block > 0 ? 1 : 0);
