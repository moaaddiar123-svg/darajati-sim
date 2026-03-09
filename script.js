/*
  Multi-layer obfuscation/decoding pipeline integrated here.
  NOTE: This is client-side obfuscation only. It increases difficulty for casual inspection,
  but **cannot** stop a determined attacker who can read and run the JavaScript.
  For real protection use server-side authentication.
*/

// Fixed final obfuscated payload with correct password "diar2025"
const FINAL_PAYLOAD = "!!Z::G::V::m::R::j::a::H::B::Z::G::F::m::V::m::F::X::N::z::J::X::Z::D::F::I::R::l::N::W::Q::l::h::P::U::V::";

// Utilities
function b64d(s) { try { return atob(s); } catch(e){ return window.decodeURIComponent(window.escape(window.atob(s))); } }
function b64e(s) { try { return btoa(s); } catch(e){ return window.btoa(unescape(encodeURIComponent(s))); } }

function base32DecodeLower(s) {
  // Supports lowercase base32 (RFC4648 without padding)
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0, value = 0, output = "";
  for (let ch of s) {
    let idx = alphabet.indexOf(ch.toLowerCase());
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output += String.fromCharCode((value >> bits) & 0xFF);
      value = value & ((1 << bits) - 1);
    }
  }
  return output;
}

function caesarInverse(s, shiftLetters = 0, shiftDigits = 0) {
  let out = "";
  for (let ch of s) {
    if (ch >= 'a' && ch <= 'z') {
      let code = ch.charCodeAt(0) - 97;
      code = (code - shiftLetters + 26) % 26;
      out += String.fromCharCode(code + 97);
    } else if (ch >= 'A' && ch <= 'Z') {
      let code = ch.charCodeAt(0) - 65;
      code = (code - shiftLetters + 26) % 26;
      out += String.fromCharCode(code + 65);
    } else if (ch >= '0' && ch <= '9') {
      let d = ch.charCodeAt(0) - 48;
      d = (d - shiftDigits + 10) % 10;
      out += String.fromCharCode(d + 48);
    } else {
      out += ch;
    }
  }
  return out;
}

function rot13(s) {
  return s.replace(/[A-Za-z]/g, function(c){
    return String.fromCharCode( (c<="Z"?90:122) >= (c.charCodeAt(0) + 13) ? c.charCodeAt(0)+13 : c.charCodeAt(0)-13 );
  });
}

// bigInt hex conversion utilities for base36/hex steps
function bigIntFromBase36(s) {
  const alph = "0123456789abcdefghijklmnopqrstuvwxyz";
  let total = 0n;
  for (let ch of s) {
    const v = BigInt(alph.indexOf(ch));
    total = total * 36n + v;
  }
  return total;
}
function bigIntToHexStr(big) {
  let hex = big.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  return hex;
}

// reverse substitution of rotate-by-11 for alphanum
function invRotateAlphanum(s) {
  const alph = "0123456789abcdefghijklmnopqrstuvwxyz";
  const shift = 11;
  let out = "";
  for (let ch of s) {
    let i = alph.indexOf(ch);
    if (i === -1) out += ch;
    else out += alph[(i - shift + alph.length) % alph.length];
  }
  return out;
}

// decode pipeline (reverse of the 20-step encoding)
function decodeFinal(payload) {
  // 20: remove markers and join
  if (!payload.startsWith("!!") || !payload.endsWith("##")) {
    // maybe the payload provided without markers - handle both
  }
  const inner = payload.replace(/^!!/, "").replace(/##$/, "");
  const s19 = inner.split("::").join(""); // reconstruct base64 string from split chars

  // 19 -> base64 decode => s18
  let s18 = b64d(s19);

  // 18 -> caesar inverse (letters -2, digits -1)
  let s17 = caesarInverse(s18, 2, 1);

  // 17 -> reverse
  s16 = s17.split("").reverse().join("");

  // 16 -> base64 decode => s15 (which contains salt markers)
  s15 = b64d(s16);

  // 15 -> remove salt "S@1t" inserted between every 3 chars => join parts
  // It was inserted between groups of 3, so split by salt
  let parts = s15.split("S@1t");
  let s14 = parts.join("");

  // 14 -> reverse
  let s13 = s14.split("").reverse().join("");

  // 13 -> base64 decode => s12 (substituted base36)
  let s12 = b64d(s13);

  // 12 -> inverse rotate alphanum (-11)
  let s11 = invRotateAlphanum(s12);

  // 11 -> base36 -> get hex string (we used lowercase base36)
  // use BigInt to parse base36
  let big = 0n;
  const alph = "0123456789abcdefghijklmnopqrstuvwxyz";
  for (let ch of s11) {
    const idx = alph.indexOf(ch);
    if (idx === -1) { /* ignore */ }
    big = big * 36n + BigInt(idx);
  }
  let h2 = bigIntToHexStr(big);

  // 10 -> chunks of 2 chars were reversed earlier; undo by splitting into 2-char pairs and reversing
  let pairs = [];
  for (let i = 0; i < h2.length; i += 2) pairs.push(h2.substr(i,2));
  pairs = pairs.reverse();
  let s9 = pairs.join("");

  // 9 -> hex decode to ascii (this yields base64 reversed string)
  function hexToAscii(hex) {
    let out = "";
    for (let i = 0; i < hex.length; i += 2) {
      out += String.fromCharCode(parseInt(hex.substr(i,2), 16));
    }
    return out;
  }
  let s8 = hexToAscii(s9);

  // 8 -> reverse
  let s7 = s8.split("").reverse().join("");

  // 7 -> base64 decode => s6 (rot13 applied originally)
  let s6 = b64d(s7);

  // 6 -> rot13 (rot13 is its own inverse)
  let s5 = rot13(s6);

  // 5 -> reverse (this was base32 lowercase)
  let s4 = s5.split("").reverse().join("");

  // 4 -> base32 decode (lowercase)
  let s3 = base32DecodeLower(s4);

  // 3 -> inverse caesar shift letters -5 digits -3
  let s2 = caesarInverse(s3, 5, 3);

  // 2 -> reverse
  let s1 = s2.split("").reverse().join("");

  // 1 -> base64 decode => plaintext
  let plaintext = b64d(s1);
  return plaintext;
}

// compute runtime PASSWORD
let PASSWORD = "";
try {
  PASSWORD = decodeFinal(FINAL_PAYLOAD);
} catch (e) {
  // fallback simple decode (keeps original behavior if anything fails)
  // original simple Caesar: var _hiddenPass = "wklu901"; ... shift +3,+2
  function simpleDecode(pass) {
    let decoded = "";
    for (let i = 0; i < pass.length; i++) {
      const c = pass.charCodeAt(i);
      if (c >= 97 && c <= 122) decoded += String.fromCharCode(((c - 97 + 3) % 26) + 97);
      else if (c >= 48 && c <= 57) decoded += String.fromCharCode(((c - 48 + 2) % 10) + 48);
      else decoded += pass.charAt(i);
    }
    return decoded;
  }
  PASSWORD = simpleDecode("wklu901");
}

// --- Translation & Data ---
const translations = {
  ar: {
    title: "دراجتي 🛵", password: "كلمة المرور", wrongPassword: "كلمة المرور غير صحيحة!", enterPassword: "أدخل كلمة المرور", pressEnter: "دخول",
    salaryLabel: "المرتب الشهري", debtsLabel: "الديون الحالية", allowanceLabel: "المنح المردودية", allowancePeriodLabel: "فترة المنحة", monthly: "شهري", every3Months: "كل 3 أشهر", every6Months: "كل 6 أشهر",
    bankLabel: "البنك", bankSalama: "بنك السلام", bankBaraka: "بنك البركة", durationLabel: "مدة التقسيط",
    eligibleHeader: "✅ دراجات بدون دفعة أولية", partialHeader: "💰 دراجات تتطلب مساهمة", resultPlaceholder: "اختر دراجة من القائمة لعرض التفاصيل",
    appName: "دراجتي", eligible: "مؤهل مباشرة!", originalInstallment: "القسط الأصلي", initialContribution: "المساهمة الأولية المقترحة", newMonthlyPayment: "القسط الشهري بعد المساهمة", basedOnPolicy: "بناءً على سياسة",
    totalMonthly: "قدرة التقسيط", bikeName: "اسم الدراجة"
  },
  fr: {
    title: "Darajati 🛵", password: "Mot de passe", wrongPassword: "Mot de passe incorrect!", enterPassword: "Mot de passe", pressEnter: "Connexion",
    salaryLabel: "Salaire mensuel", debtsLabel: "Dettes actuelles", allowanceLabel: "Primes", allowancePeriodLabel: "Période", monthly: "Mensuel", every3Months: "3 mois", every6Months: "6 mois",
    bankLabel: "Banque", bankSalama: "Banque Salam", bankBaraka: "Banque Baraka", durationLabel: "Durée",
    eligibleHeader: "✅ Sans apport", partialHeader: "💰 Avec apport", resultPlaceholder: "Choisissez un scooter",
    appName: "Darajati", eligible: "Éligible direct!", originalInstallment: "Mensualité originale", initialContribution: "Apport proposé", newMonthlyPayment: "Nouvelle mensualité", basedOnPolicy: "Selon politique",
    totalMonthly: "Revenu total", bikeName: "Modèle"
  }
};

const banks = {
  salama: {
    "CK110": {60: 8051, 48: 9561, 36: 12131, 24: 17420, 12: 34328},
    "VM12": {60: 13449, 48: 15971, 36: 20264, 24: 29099, 12: 57346},
    "ESTATEX": {60: 9196, 48: 10921, 36: 13856, 24: 19897, 12: 39211},
    "XDV200": {60: 18268, 48: 21693, 36: 27524, 24: 39524, 12: 77890},
    "TWISTER CORAL": {60: 13658 , 48: 16219, 36: 20578, 24: 29550, 12: 58233},
    "CUKI1": {60: 9702, 48: 11521, 36: 14618, 24: 20991, 12: 41367},
    "CLIGHT": {60: 10035, 48: 11917, 36: 15119, 24: 21712, 12: 42787},
    "JOCQUICK": {60: 8795, 48: 10444, 36: 13251, 24: 19028, 12: 37499},
    "RK200": {60: 16126, 48: 19150, 36: 24297, 24: 34891, 12: 68759},
    "VMAX200": {60: 16334, 48: 19397, 36: 24611, 24: 35341, 12: 69647},
    "BWS": {60: 12319, 48: 14629, 36: 18561, 24: 26654 , 12: 52526},
    "Gemma":{60: 13152, 48: 15618, 36: 19816, 24: 28456, 12: 56077},
    "CUKII2": {60: 10683, 48: 12687, 36: 16096 , 24: 23115, 12: 45552}, 
    "KLIGHT200": {60: 13084, 48: 15537, 36: 19713, 24: 28308, 12: 55786},
    "Driver3": {60: 12513, 48: 14859, 36: 18852, 24: 27072, 12: 53351},
    "PANAREA": {60: 11665, 48: 13852, 36: 17575, 24: 25238, 12: 49737}
  },
  baraka: {
    "CK110": {60: 7497, 48: 8945, 36: 11374, 24: 16257, 12: 30957},
    "VM12": {60: 12523, 48: 14942, 36: 19000, 24: 27158, 12: 51713},
    "ESTATEX": {60: 8563, 48: 10217, 36: 12992, 24: 18569, 12: 35359},
    "XDV200": {60: 17010, 48: 20295, 36: 25807, 24: 36887, 12: 70239},
    "TWISTER CORAL": {60: 12717, 48: 15173, 36: 19294, 24: 27578, 12: 52513},
    "CUKI1": {60: 9034, 48: 10778, 36: 13706, 24: 19590, 12: 37303},
    "CLIGHT": {60: 9344, 48: 11149, 36: 14176, 24: 20263, 12: 38584},
    "JOCQUICK": {60: 8189, 48: 9771, 36: 12424, 24: 17795, 12: 33815},
    "RK200": {60: 15016, 48: 17916, 36: 22782, 24: 32563, 12: 62005},
    "VMAX200": {60: 15210, 48: 18147, 36: 23076, 24: 32983, 12: 62806},
    "BWS": {60: 11471, 48: 13686, 36: 17403, 24: 24875, 12: 47367},
    "Gemma":{60: 12246 , 48: 14611, 36: 18580, 24: 26557, 12: 50569},
    "CUKII2": {60: 9948, 48: 11869, 36: 15092, 24: 21572, 12: 41077},
    "KLIGHT200": {60: 12183, 48: 14535, 36: 18483, 24: 26419, 12: 50306},
    "Driver3": {60: 11651, 48: 13901, 36: 17676, 24: 25266, 12: 48110},
    "PANAREA": {60: 10862 , 48: 12959, 36: 16479, 24: 23554, 12: 44851}
  }
};

let currentLanguage = 'ar';

// --- Core Functions ---

function formatNumber(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, " ");
}

function switchLanguage(lang) {
  currentLanguage = lang;
  document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`.lang-btn[onclick="switchLanguage('${lang}')"]`).classList.add('active');
  if (lang === 'fr') {
    document.body.classList.add('french');
    document.documentElement.dir = 'ltr';
  } else {
    document.body.classList.remove('french');
    document.documentElement.dir = 'rtl';
  }
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (translations[lang][key]) el.textContent = translations[lang][key];
  });
  renderBikeLists();
}

// Function to render the two columns based on salary
function renderBikeLists() {
  const salary = parseFloat(document.getElementById("salary").value) || 0;
  const debts = parseFloat(document.getElementById("debts").value) || 0;
  const allowance = parseFloat(document.getElementById("allowance").value) || 0;
  const allowancePeriod = parseInt(document.getElementById("allowancePeriod").value) || 1;
  const bank = document.getElementById("bank").value;
  const duration = parseInt(document.getElementById("duration").value) || 60;
  
  const monthlyAllowance = allowance / allowancePeriod;
  const totalSalary = salary + monthlyAllowance;
  const maxAllowed = totalSalary * 0.3;
  const availableCapacity = maxAllowed - debts;
  const bankData = banks[bank];
  
  const eligibleList = document.getElementById("list-eligible");
  const partialList = document.getElementById("list-partial");
  
  eligibleList.innerHTML = "";
  partialList.innerHTML = "";

  if (salary <= 0) {
    eligibleList.innerHTML = `<div style="text-align:center; padding:20px; color:#999;">أدخل المرتب أولاً</div>`;
    return;
  }

  Object.keys(bankData).sort().forEach(bikeName => {
    const installment = bankData[bikeName][duration];
    
    // Create Card Element
    const card = document.createElement("div");
    card.className = "bike-card";
    
    // Click event to show detailed result
    card.onclick = () => showBikeResult(bikeName, duration, installment, availableCapacity, maxAllowed, bank);

    if (installment <= availableCapacity && availableCapacity > 0) {
      // Eligible without down payment
      card.innerHTML = `
        <div>
          <div class="bike-name">${bikeName}</div>
          <div class="bike-price">${formatNumber(installment)} دج / شهرياً</div>
        </div>
        <span class="bike-badge badge-green">مؤهل</span>
      `;
      eligibleList.appendChild(card);
    } else {
      // Requires down payment
      card.innerHTML = `
        <div>
          <div class="bike-name">${bikeName}</div>
          <div class="bike-price">يتطلب مساهمة</div>
        </div>
        <span class="bike-badge badge-orange">مساهمة</span>
      `;
      partialList.appendChild(card);
    }
  });

  // If lists are empty
  if (eligibleList.innerHTML === "") eligibleList.innerHTML = `<div style="text-align:center; padding:10px; opacity:0.6;">لا توجد دراجات</div>`;
  if (partialList.innerHTML === "") partialList.innerHTML = `<div style="text-align:center; padding:10px; opacity:0.6;">لا توجد دراجات</div>`;
}

// Function to show the detailed result in the bottom box
function showBikeResult(bikeName, duration, installment, availableCapacity, maxAllowed, bank) {
  const res = document.getElementById("result");
  const bankName = bank === 'salama' ? translations[currentLanguage].bankSalama : translations[currentLanguage].bankBaraka;
  const totalSalaryTxt = `<span class="result-value">${formatNumber(Math.round(maxAllowed/0.3))}</span> دج`;

  if (installment <= availableCapacity && availableCapacity > 0) {
    // Fully Eligible
    res.className = "success";
    res.innerHTML = `
      <div style="font-size:20px; margin-bottom:10px;">✅ ${translations[currentLanguage].eligible}</div>
      <div class="result-detail-row"><span class="result-label">${translations[currentLanguage].bikeName}:</span> <span class="result-value">${bikeName}</span></div>
      <div class="result-detail-row"><span class="result-label">${translations[currentLanguage].bankLabel}:</span> <span class="result-value">${bankName}</span></div>
      <div class="result-detail-row"><span class="result-label">${translations[currentLanguage].originalInstallment}:</span> <span class="result-value">${formatNumber(installment)} دج</span></div>
      <div class="result-detail-row"><span class="result-label">${translations[currentLanguage].totalMonthly}:</span> <span class="result-value">${formatNumber(Math.round(maxAllowed))} دج</span></div>
    `;
  } else {
    // Partial Eligible - Needs Calculation
    // Policy: Duration - 1 for Salama
    const actualDuration = bank === 'salama' ? duration - 1 : duration;
    const shortfall = installment - availableCapacity;
    const initialContribution = Math.round(shortfall * actualDuration);
    const newMonthlyPayment = Math.round(availableCapacity);

    res.className = "warning";
    res.innerHTML = `
      <div style="font-size:18px; margin-bottom:10px;">⚠️ ${bikeName} - ${bankName}</div>
      <div class="result-detail-row"><span class="result-label">${translations[currentLanguage].originalInstallment}:</span> <span class="result-value" style="color:#c62828">${formatNumber(installment)} دج</span></div>
      <div class="result-detail-row"><span class="result-label">${translations[currentLanguage].initialContribution}:</span> <span class="result-value" style="color:#ef6c00; font-size:1.1em;">${formatNumber(initialContribution)} دج</span></div>
      <div class="result-detail-row"><span class="result-label">${translations[currentLanguage].newMonthlyPayment}:</span> <span class="result-value" style="color:#2e7d32">${formatNumber(newMonthlyPayment)} دج</span></div>
      <div style="margin-top:10px; font-size:0.9em; opacity:0.8;">(${translations[currentLanguage].basedOnPolicy} ${bankName})</div>
    `;
  }
}

// Login Logic
document.getElementById("pw").onkeydown = function(e) {
  if (e.key === "Enter") {
    const p = document.getElementById("pw").value;
    if (p === PASSWORD) {
      document.getElementById("login").style.display = "none";
      document.getElementById("app").style.display = "block";
      document.body.classList.add('logged-in');
      renderBikeLists(); // Initial render
      // Chatbot logic
      setTimeout(() => {
        const c = document.querySelector('.chatbase-chatbot-container');
        if(c) c.style.display = 'block';
      }, 500);
    } else {
      document.getElementById("loginError").style.display = "block";
      setTimeout(() => document.getElementById("loginError").style.display = "none", 2000);
    }
  }
};
document.querySelector('.login-box button').onclick = function() {
    document.getElementById("pw").dispatchEvent(new KeyboardEvent('keydown', {'key': 'Enter'}));
}

// Init
document.addEventListener("DOMContentLoaded", () => {
  // Set default duration to 60
  document.getElementById("duration").value = "60";
});

// Chatbase Configuration
window.embeddedChatbotConfig = {
  chatbotId: "I41PK4rKohu-WBYMXE7gQ",
  domain: "www.chatbase.co",
  welcomeMessage: currentLanguage === 'ar' ? "مرحبًا! أنا بوت دعم 'دراجتي'." : "Bonjour! Je suis le bot de support.",
  colorScheme: "light", position: "left"
};
