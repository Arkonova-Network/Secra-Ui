/*
Secra UI - JavaScript library for non-custodial wallet connection (updated)
Features added:
 - Updated styles (mnemonic 4-col grid + Verification grid 2-col)
 - Loads libsodium (libsodium-wrappers) async and generates two keypairs (signing + box) derived from seed
 - Saves encrypted private key into IndexedDB (encrypted with AES-GCM derived from PIN)
 - Keeps compatibility with original flows (create/import/auth)
 - Exposes helpers for retrieving encrypted key from IDB
Version: 1.5.0
*/

(function (global) {
  const DEFAULTS = {
    buttonSelector: null,
    redirectUrl: window.location.href,
    serverUrl: 'https://arkonova.ru/secra/api',
    buildVersion: '1.5.0',
    lang: 'EN',
    langCdn: 'https://raw.githubusercontent.com/Arkonova-Network/Secra-Ui/main/lang/',
    ethersCdn: 'https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js',
    bip39lib: 'https://cdn.jsdelivr.net/gh/Arkonova-Network/Secra-Ui@master/dist/bip39-browser.js',
    bufferLib: 'https://cdn.jsdelivr.net/gh/Arkonova-Network/Secra-Ui@master/dist/buffer.umd.js',
    sodiumCdn: 'https://cdn.jsdelivr.net/gh/jedisct1/libsodium.js@0.7.15/dist/browsers/sodium.js',
    versionCheckUrl: 'https://api.github.com/repos/Arkonova-Network/Secra-Ui/releases/latest'
  };

  const KEYS = {
    avatar: 'Secra_Avatar',
    name: 'Secra_Name',
    address: 'Secra_Adress',
    privEnc: 'Secra_Privat_encrypted', // NOTE: pointer/legacy
    pinHash: 'Secra_pin_hash',
    dataHash: 'Secra_Data_Hash',
    sodium_pub : "sodium_pub"
  };

  // i18n dictionary fallback
  let I18N = {};
  async function loadLanguage(lang, langCdn) {
    try {
      const resp = await fetch(`${langCdn}${lang}.json`);
      if (!resp.ok) throw new Error('Language file not found');
      I18N = await resp.json();
    } catch (e) {
      console.warn('Falling back to default translations');
      I18N = {
        'welcome': 'Добро пожаловать в Secra - Arkonova Network',
        'choose_action': 'Выберите действие:',
        'create_id': 'Создать идентификатор',
        'import_id': 'Добавить Идентификатор',
        'authorize': 'Авторизоваться',
        'enter_pin': 'Введите PIN',
        'unlock': 'Разблокировать',
        'wrong_pin': 'Неверный PIN',
        'unlocked': 'Разблокировано!',
        'authorization': 'Авторизация',
        'account_found': 'Обнаружена запись Secra:',
        'create_advantages': 'Преимущества не кастодиального кошелька',
        'advantages_text': 'Полный контроль над средствами • Никто кроме вас не имеет доступа • Максимальная безопасность',
        'policy_agree': 'Создавая ID вы соглашаетесь с политикой Arkonova Network',
        'lets_create': 'Приступим к созданию',
        'save_phrase': 'Запишите фразу и нажмите "Сохранить фразу"',
        'save_phrase_btn': 'Сохранить фразу',
        'verify_phrase': 'Проверка записи фразы',
        'enter_word': 'Введите слово №',
        'verify': 'Проверить',
        'verification_passed': 'Проверка пройдена!',
        'create_profile': 'Создание профиля',
        'choose_avatar': 'Выберите аватарку:',
        'enter_nickname': 'Введите никнейм:',
        'create_profile_btn': 'Создать профиль',
        'enter_pin_security': 'Для повышения безопасности введите PIN для шифрования приватного ключа',
        'set_pin': 'Установить PIN',
        'id_created': 'ID создан!',
        'welcome_to_secra': 'Приветствуем вас в Secra!',
        'forward': 'Вперёд!',
        'welcome_back': 'С возвращением!',
        'enter_seed': 'Введите мнемо-фразу (seed):',
        'import_btn': 'Импортировать',
        'checking_server': 'Проверяем данные на сервере...',
        'user_not_found': 'Пользователь с таким идентификатором не найден',
        'verification_failed': 'Данные не соответствуют серверным',
        'next': 'Далее',
        'back': 'Назад'
      };
    }
  }
  function t(key) { return I18N[key] || key; }

  // --- Crypto helpers ---
  async function ensureEthers(ethersCdn) {
    if (global.ethers) return global.ethers;
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = ethersCdn;
      s.onload = () => {
        if (global.ethers) resolve(global.ethers);
        else reject(new Error('ethers failed to load'));
      };
      s.onerror = () => reject(new Error('Failed to load ethers.js'));
      document.head.appendChild(s);
    });
  }

  async function ensureBip39(bip39Cdn) {
    if (global.bip39) return global.bip39;
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = bip39Cdn;
      s.onload = () => {
        if (global.bip39) resolve(global.bip39);
        else reject(new Error('bip39 failed to load'));
      };
      s.onerror = () => reject(new Error('Failed to load bip39.js'));
      document.head.appendChild(s);
    });
  }

  async function ensurebuffer(bufferLib) {
    if (window.Buffer?.from && window.Buffer?.isBuffer) return window.Buffer;
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = bufferLib;
      s.onload = () => {
        let BufferCtor;
        if (window.Buffer?.from && window.Buffer?.isBuffer) {BufferCtor = window.Buffer;}
        else if (window.Buffer?.default?.Buffer) {BufferCtor = window.Buffer.default.Buffer;}
        if (BufferCtor) {window.Buffer = BufferCtor;resolve(BufferCtor);}
        else {reject(new Error('Buffer failed to load'));}
      };
      s.onerror = () => reject(new Error('Failed to load buffer.js'));
      document.head.appendChild(s);
    });
  }

  // Load libsodium (libsodium-wrappers)
  async function ensureSodium(sodiumCdn) {
    if (global.sodium && global.sodium.ready) return global.sodium;
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = sodiumCdn;
      s.onload = async () => {
        try {
          if (!global.sodium) return reject(new Error('libsodium not found after load'));
          await global.sodium.ready;
          resolve(global.sodium);
        } catch (e) {
          reject(e);
        }
      };
      s.onerror = () => reject(new Error('Failed to load libsodium'));
      document.head.appendChild(s);
    });
  }

  // small converters
  function str2ab(str) { return new TextEncoder().encode(str); }
  function ab2hex(buf) { return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }
  function hex2ab(hex) { const buf = new Uint8Array(hex.length/2); for (let i=0;i<buf.length;i++) buf[i]=parseInt(hex.substr(i*2,2),16); return buf.buffer; }
  async function sha256Hex(text) { return ab2hex(await crypto.subtle.digest('SHA-256', str2ab(text))); }

  async function deriveKeyFromPin(pin, salt) {
    const keyMaterial = await crypto.subtle.importKey('raw', str2ab(pin), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({
      name:'PBKDF2',
      salt:str2ab(salt),
      iterations:120000,
      hash:'SHA-256'
    }, keyMaterial, {
      name:'AES-GCM',
      length:256
    }, false, ['encrypt','decrypt']);
  }

  async function encryptWithKey(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, str2ab(plaintext));
    return ab2hex(iv.buffer)+':'+ab2hex(ct);
  }

  async function decryptWithKey(key, cipherText) {
    const [ivHex, ctHex] = cipherText.split(':');
    const iv = new Uint8Array(hex2ab(ivHex));
    const ct = hex2ab(ctHex);
    const ptBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(ptBuf);
  }

  async function computeDataHash(avatar, address, privEnc, pinHash) {
    return await sha256Hex(avatar + '||' + address + '||' + privEnc + '||' + pinHash);
  }

  // --- IndexedDB helpers (for storing encrypted private key) ---
  function openIDB() {
    return new Promise((resolve, reject) => {
      const rq = indexedDB.open('secra-store', 1);
      rq.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('keys')) {
          db.createObjectStore('keys', { keyPath: 'id' });
        }
      };
      rq.onsuccess = () => resolve(rq.result);
      rq.onerror = () => reject(rq.error);
    });
  }

  async function idbPut(id, value) {
    const db = await openIDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readwrite');
      const store = tx.objectStore('keys');
      store.put({ id, value, updatedAt: Date.now() });
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    });
  }

  async function idbGet(id) {
    const db = await openIDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readonly');
      const store = tx.objectStore('keys');
      const rq = store.get(id);
      rq.onsuccess = () => resolve(rq.result ? rq.result.value : null);
      rq.onerror = () => reject(rq.error);
    });
  }

  async function idbDelete(id) {
    const db = await openIDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readwrite');
      const store = tx.objectStore('keys');
      const rq = store.delete(id);
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
    });
  }

  // --- mnemonic & wallet generation ---
  function generateMnemonic() {
    const entropy = crypto.getRandomValues(new Uint8Array(32));
    const hex = Array.from(entropy).map(b => b.toString(16).padStart(2, '0')).join('');
    const mnemonic = global.bip39.entropyToMnemonic(hex);
    return mnemonic;
  }

  // Generate wallet from mnemonic (ethers) and sodium keypairs async
  async function mnemonicToWallet(mnemonic, ethers, sodium) {
    const phrase = Array.isArray(mnemonic) ? mnemonic.join(' ').trim() : mnemonic.trim();

    const wallet = ethers.Wallet.fromPhrase ? ethers.Wallet.fromPhrase(phrase) : ethers.Wallet.fromMnemonic(phrase);

    // compute stable seed (SHA-256)
    const seed = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(phrase)));

    // derive libsodium keypairs (sign + box) using generic hash to separate seeds
    await sodium.ready;
    const seedSign = sodium.crypto_generichash(32, seed, sodium.from_string('secra-sign'));
    const seedBox = sodium.crypto_generichash(32, seed, sodium.from_string('secra-box'));

    const signKP = sodium.crypto_sign_seed_keypair(seedSign);
    const boxKP = sodium.crypto_box_seed_keypair(seedBox);

    return {
      wallet,
      sodiumKeys: {
        sign: {
          publicKey: sodium.to_base64(signKP.publicKey),
          privateKey: sodium.to_base64(signKP.privateKey)
        },
        box: {
          publicKey: sodium.to_base64(boxKP.publicKey),
          privateKey: sodium.to_base64(boxKP.privateKey)
        }
      }
    };
  }

  // --- UI utilities ---
  function createEl(tag, attrs = {}, children = []) {
    const el = document.createElement(tag);
    for (const k in attrs) {
      if (k === 'class') el.className = attrs[k];
      else if (k === 'html') el.innerHTML = attrs[k];
      else el.setAttribute(k, attrs[k]);
    }
    (Array.isArray(children) ? children : [children]).forEach(c => {
      if (!c) return;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return el;
  }

  const STYLE_ID = 'secra-ui-styles';
  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.innerHTML = `
/* existing styles kept + new requested styles */
      .secra-modal-backdrop { position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.6); display:flex; justify-content:center; align-items:center; z-index:9999; }
      .secra-modal { background: #0f1a25; padding: 24px; border-radius: 12px; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 4px 20px rgba(0,0,0,0.15); position: relative; color: #fff; }
      .secra-modal h3 { margin-top:0; margin-bottom:16px; color: #fff; }
      .secra-btn { background: linear-gradient(90deg, #2d6fe8, #6fb4ff); color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; margin: 8px 4px; font-size: 14px; font-weight: 500; transition: background 0.2s; }
      .secra-btn:hover { filter: brightness(0.95); }
      .secra-btn-secondary { background: #6b7280; color: white; }
      .secra-notify { position: fixed; top: 20px; right: 20px; background: #0f1a25; padding: 16px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); display:flex; gap:12px; z-index:9998; max-width:350px; border-left:4px solid #4f46e5; flex-wrap:wrap; color:white; }
      .secra-modal input, .secra-modal textarea { padding: 12px; border: 1px solid #d1d5db; border-radius:8px; margin:8px 0; width:100%; box-sizing: border-box; font-size:14px; }
      .secra-modal input:focus, .secra-modal textarea:focus { outline:none; border-color:#4f46e5; box-shadow: 0 0 0 3px rgba(79,70,229,0.1); }
      .secra-close-btn { position:absolute; top:12px; right:16px; background:none; border:none; font-size:24px; cursor:pointer; color:#6b7280; width:32px; height:32px; display:flex; align-items:center; justify-content:center; border-radius:50%; }
      .secra-close-btn:hover { background:#f3f4f6; color:#374151; }
      .secra-avatar-grid { display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; margin:16px 0; }
      .secra-avatar-option { width:60px; height:60px; border-radius:50%; cursor:pointer; border:3px solid transparent; transition: border-color 0.2s; }
      .secra-avatar-option:hover { border-color:#4f46e5; }
      .secra-avatar-option.selected { border-color:#4f46e5; box-shadow:0 0 0 2px rgba(79,70,229,0.2); }
      .secra-step-indicator { display:flex !important; flex-direction:row !important; justify-content:center; gap:10px; margin-top:20px; }
      .secra-step { width:12px; height:12px; border-radius:50%; background:#e5e7eb; margin:0 4px; }
      .secra-step.active { background:#4f46e5; }
      .secra-step.completed { background:#10b981; }
      .secra-loading { display:inline-block; width:20px; height:20px; border:3px solid #f3f3f3; border-top:3px solid #4f46e5; border-radius:50%; animation: spin 1s linear infinite; margin-right:8px; }
      @keyframes spin { 0% { transform: rotate(0deg);} 100% { transform: rotate(360deg);} }
      .secra-notify img { width: 48px; height: 48px; border-radius: 50%; object-fit: cover;}
      /* NEW: user's requested styles */
      .secra-mnemonic-grid {     display: grid !important;     grid-template-columns: repeat(4, 1fr) !important; /* 4 столбца */     grid-auto-rows: auto !important; /* высота под содержимое */     gap: 10px !important;     margin-top: 15px !important; }
      .secra-mnemonic-grid > div {     background: #04102b !important;     border: 1px solid #ddd !important;     border-radius: 8px !important;     padding: 10px !important;     text-align: center !important;     font-size: 14px !important;     box-sizing: border-box !important;     width: 100% !important;     color:#2d6fe8 !important; }
      .VerificationtDiv {     display: grid !important;     grid-template-columns: repeat(2, 1fr) !important; /* 2 столбца */     gap: 15px !important;     margin-top: 15px !important;     align-items: start !important; }
      .VerificationtDiv label {     display: block !important;     font-weight: 500 !important;     margin-bottom: 5px !important; }
      .VerificationtDiv input {     width: 100% !important;     padding: 8px 10px !important;     border: 1px solid #ccc !important;     border-radius: 6px !important;     box-sizing: border-box !important;     font-size: 14px !important;     background: #f9f9f9 !important;     transition: border-color 0.2s ease !important; }
      .VerificationtDiv input:focus {     border-color: #4a90e2 !important;     outline: none !important;     background: #fff !important; }
    `;
    document.head.appendChild(style);
  }

  // server communication helper
  async function serverRequest(url, data) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      return await response.json();
    } catch (error) {
      console.error('Server request failed:', error);
      return { success: false, error: error.message };
    }
  }

  // Notification and modal
  function showNotification({ avatar, name, address, onAuth }) {
    injectStyles();
    const wrap = createEl('div', { class: 'secra-notify' }, [
      createEl('img', { src: avatar || 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="%234f46e5"><circle cx="12" cy="12" r="10"/></svg>', alt: 'avatar' }),
      createEl('div', { html: `<strong>${t('account_found')}</strong><br><b>${name}</b><br><small>${address}</small>` })
    ]);
    const btn = createEl('button', { class: 'secra-btn' }, t('authorize'));
    btn.onclick = () => {
      onAuth();
      if (document.body.contains(wrap)) document.body.removeChild(wrap);
    };
    wrap.appendChild(btn);
    document.body.appendChild(wrap);
  }

  function showModal({ title, contentEl, onClose, hideClose = false }) {
    injectStyles();
    const backdrop = createEl('div', { class: 'secra-modal-backdrop' });
    const modal = createEl('div', { class: 'secra-modal' }, [
      createEl('h3', { html: title }),
      contentEl
    ]);

    const closeModal = () => {
      if (document.body.contains(backdrop)) document.body.removeChild(backdrop);
      if (onClose) onClose();
    };

    if (!hideClose) {
      const closeBtn = createEl('button', { class: 'secra-close-btn' }, '×');
      closeBtn.onclick = closeModal;
      modal.insertBefore(closeBtn, modal.firstChild);
    }

    backdrop.onclick = (e) => {
      if (e.target === backdrop && !hideClose) closeModal();
    };

    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);
    return { backdrop, closeModal };
  }

  // Main SecraUI
  function SecraUI(cfg) {
    this.cfg = Object.assign({}, DEFAULTS, cfg || {});
    this.currentModal = null;
    this.currentStep = 0;
    this.creationData = {};
    this.sodium = null;
    console.log('SecraUI build:', this.cfg.buildVersion);
    this._init();
  }

  SecraUI.prototype._init = async function() {
    try {
      await this._checkVersion();
      await loadLanguage(this.cfg.lang, this.cfg.langCdn);
      this.ethers = await ensureEthers(this.cfg.ethersCdn);
      this.bip39 = await ensureBip39(this.cfg.bip39lib);
      this.Buffer = await ensurebuffer(this.cfg.bufferLib);
      this.sodium = await ensureSodium(this.cfg.sodiumCdn);

      if (this.cfg.buttonSelector) {
        const btn = document.querySelector(this.cfg.buttonSelector);
        if (btn) btn.addEventListener('click', () => this.openMainModal());
      }

      await this._checkExistingAccount();
    } catch (error) {
      console.error('SecraUI initialization error:', error);
    }
  };

  SecraUI.prototype._checkVersion = async function() {
    try {
      const response = await fetch(this.cfg.versionCheckUrl);
      const data = await response.json();
      const latestVersion = data.tag_name || data.name;
      if (latestVersion && latestVersion !== this.cfg.buildVersion) {
        console.warn(`New version available: ${latestVersion} (current: ${this.cfg.buildVersion})`);
      }
    } catch (error) {
      console.warn('Version check failed:', error);
    }
  };

  SecraUI.prototype._checkExistingAccount = async function() {
    const avatar = localStorage.getItem(KEYS.avatar);
    const name = localStorage.getItem(KEYS.name);
    const address = localStorage.getItem(KEYS.address);
    const privEncLegacy = localStorage.getItem(KEYS.privEnc); // legacy pointer if present
    const pinHash = localStorage.getItem(KEYS.pinHash);
    const dataHash = localStorage.getItem(KEYS.dataHash);

    if (avatar && name && address && (privEncLegacy || pinHash) && dataHash) {
      // If privEncLegacy exists, compute using it; prefer IDB later
      const computed = await computeDataHash(avatar, address, privEncLegacy || 'idb-stored', pinHash || '');
      if (computed === dataHash) {
        showNotification({
          avatar,
          name,
          address,
          onAuth: () => this._onAuthRequest()
        });
      } else {
        console.warn('Data integrity check failed');
      }
    }
  };

  // Authorization flow
  SecraUI.prototype._onAuthRequest = function() {
    const input = createEl('input', { placeholder: t('enter_pin'), type: 'password', maxlength: '6' });
    const btn = createEl('button', { class: 'secra-btn' }, t('unlock'));

    btn.onclick = async () => {
      try {
        const pin = input.value;
        if (!pin) return;

        const storedPinHash = localStorage.getItem(KEYS.pinHash);
        const enteredPinHash = await sha256Hex(pin);

        if (enteredPinHash !== storedPinHash) {
          alert(t('wrong_pin'));
          return;
        }

        const address = localStorage.getItem(KEYS.address);
        const salt = 'secra-salt:' + address;
        const aesKey = await deriveKeyFromPin(pin, salt);

        // try to get encrypted private key from IDB first, fallback to localStorage
        const encPriv = await idbGet(`priv:${address}`) || localStorage.getItem(KEYS.privEnc);
        if (!encPriv) { alert('Encrypted private key not found'); return; }

        const privateKey = await decryptWithKey(aesKey, encPriv);

        // place unencrypted private key only in session for short-term use
        sessionStorage.setItem('Secra_private_unencrypted_temp', privateKey);

        if (this.currentModal) this.currentModal.closeModal();

        // Generate identification data and redirect (or verify)
        await this._generateIdentificationData(privateKey);

        // verify token on server and redirect
        fetch(this.cfg.serverUrl + '/verify_token', { headers: { 'Authorization': `Bearer ${localStorage.getItem("token")}` } })
          .then(res => res.json())
          .then(data => {
            if (data.success) {
              window.location.href = this.cfg.redirectUrl;
            } else {
              alert("Токен недействителен. Пожалуйста, войдите снова.");
            }
          })
          .catch(err => {
            console.error(err);
            alert("Ошибка проверки токена. Пожалуйста, войдите снова.");
          });

      } catch (error) {
        console.error('Auth error:', error);
        alert('Ошибка авторизации');
      }
    };

    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') btn.click();
    });

    this.currentModal = showModal({
      title: t('authorization'),
      contentEl: createEl('div', {}, [input, btn])
    });
  };

  SecraUI.prototype._generateIdentificationData = async function(privateKey) {
    const timestamp = Date.now();
    const nonce = Math.random().toString(36).substring(7);
    const message = `secra-auth:${timestamp}:${nonce}`;
    const identificationData = {
      timestamp,
      nonce,
      signature: await sha256Hex(message + privateKey)
    };
    sessionStorage.setItem('Secra_identification_data', JSON.stringify(identificationData));
  };

  // UI entry
  SecraUI.prototype.openMainModal = function() {
    const createBtn = createEl('button', { class: 'secra-btn' }, t('create_id'));
    const importBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('import_id'));

    const content = createEl('div', {}, [
      createEl('p', { html: t('welcome') }),
      createEl('p', { html: t('choose_action') }),
      createEl('div', {}, [createBtn, importBtn])
    ]);

    createBtn.onclick = () => this._startCreateFlow();
    importBtn.onclick = () => this._startImportFlow();

    this.currentModal = showModal({
      title: 'Secra - Arkonova Network',
      contentEl: content
    });
  };

  // Creation flow steps
  SecraUI.prototype._startCreateFlow = function() {
    this.currentStep = 0;
    this.creationData = {};
    this._showCreateStep();
  };

  SecraUI.prototype._showCreateStep = function() {
    const steps = [
      () => this._showAdvantages(),
      () => this._showPolicy(),
      () => this._generateAndShowMnemonic(),
      () => this._verifyMnemonic(),
      () => this._createProfile(),
      () => this._setPinAndFinalize()
    ];

    if (this.currentStep < steps.length) steps[this.currentStep]();
  };

  SecraUI.prototype._showAdvantages = function() {
    const nextBtn = createEl('button', { class: 'secra-btn' }, t('next'));
    const backBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('back'));
    const content = createEl('div', {}, [
      this._createStepIndicator(),
      createEl('h4', {}, t('create_advantages')),
      createEl('p', {}, t('advantages_text')),
      createEl('div', {}, [backBtn, nextBtn])
    ]);
    nextBtn.onclick = () => { this.currentStep++; this._showCreateStep(); };
    backBtn.onclick = () => this.openMainModal();
    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Создание ID', contentEl: content });
  };

  SecraUI.prototype._showPolicy = function() {
    const nextBtn = createEl('button', { class: 'secra-btn' }, t('lets_create'));
    const backBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('back'));
    const content = createEl('div', {}, [
      this._createStepIndicator(),
      createEl('p', {}, t('policy_agree')),
      createEl('div', {}, [backBtn, nextBtn])
    ]);
    nextBtn.onclick = () => { this.currentStep++; this._showCreateStep(); };
    backBtn.onclick = () => { this.currentStep--; this._showCreateStep(); };
    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Политика использования', contentEl: content });
  };

  SecraUI.prototype._generateAndShowMnemonic = function() {
    const mnemonic = generateMnemonic();
    this.creationData.mnemonic = mnemonic;

    const mnemonicGrid = createEl('div', { class: 'secra-mnemonic-grid' });
    mnemonic.split(' ').forEach((word, i) =>
      mnemonicGrid.appendChild(createEl('div', {}, `${i + 1}. ${word}`))
    );

    const saveBtn = createEl('button', { class: 'secra-btn' }, t('save_phrase_btn'));
    const backBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('back'));

    const content = createEl('div', {}, [
      this._createStepIndicator(),
      createEl('p', {}, t('save_phrase')),
      mnemonicGrid,
      createEl('div', {}, [backBtn, saveBtn])
    ]);

    saveBtn.onclick = () => { this.currentStep++; this._showCreateStep(); };
    backBtn.onclick = () => { this.currentStep--; this._showCreateStep(); };

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Сохранение фразы', contentEl: content });
  };

  SecraUI.prototype._verifyMnemonic = function() {
    const mnemonic = Array.isArray(this.creationData.mnemonic) ? this.creationData.mnemonic : this.creationData.mnemonic.trim().split(/\s+/);
    const randomIndices = [];
    while (randomIndices.length < 4) {
      const randomIndex = Math.floor(Math.random() * mnemonic.length);
      if (!randomIndices.includes(randomIndex)) randomIndices.push(randomIndex);
    }
    randomIndices.sort((a, b) => a - b);

    const inputs = [];
    const verificationDiv = createEl('div', { class: 'VerificationtDiv' });

    randomIndices.forEach(index => {
      const label = createEl('label', {}, `${t('enter_word')} ${index + 1}:`);
      const input = createEl('input', { type: 'text', placeholder: `Слово ${index + 1}` });
      inputs.push({ input, correctWord: mnemonic[index] });
      verificationDiv.appendChild(label);
      verificationDiv.appendChild(input);
    });

    const verifyBtn = createEl('button', { class: 'secra-btn' }, t('verify'));
    const backBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('back'));

    const content = createEl('div', {}, [
      this._createStepIndicator(),
      createEl('p', {}, t('verify_phrase')),
      verificationDiv,
      createEl('div', {}, [backBtn, verifyBtn])
    ]);

    verifyBtn.onclick = () => {
      const allCorrect = inputs.every(({ input, correctWord }) => input.value.toLowerCase().trim() === correctWord.toLowerCase());
      if (allCorrect) {
        alert(t('verification_passed'));
        this.currentStep++;
        this._showCreateStep();
      } else {
        alert('Некоторые слова введены неверно. Проверьте еще раз.');
      }
    };

    backBtn.onclick = () => { this.currentStep--; this._showCreateStep(); };

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Проверка фразы', contentEl: content });
  };

  SecraUI.prototype._createProfile = function() {
    const defaultAvatar = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="%234f46e5"><circle cx="12" cy="12" r="10"/><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" fill="white"/></svg>';
    const avatarGrid = createEl('div', { class: 'secra-avatar-grid' });
    let selectedAvatar = defaultAvatar;
    const avatarImg = createEl('img', { src: defaultAvatar, class: 'secra-avatar-option selected', alt: 'Default Avatar' });
    avatarGrid.appendChild(avatarImg);

    const uploadBtn = createEl('button', { class: 'secra-avatar-upload secra-btn-secondary' }, '+');
    avatarGrid.appendChild(uploadBtn);
    const fileInput = createEl('input', { type: 'file', accept: 'image/*', style: 'display:none' });
    avatarGrid.appendChild(fileInput);

    uploadBtn.onclick = () => fileInput.click();
    fileInput.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function(event) {
        const img = new Image();
        img.onload = function() {
          const size = Math.min(img.width, img.height);
          const offsetX = (img.width - size) / 2;
          const offsetY = (img.height - size) / 2;
          const canvas = document.createElement('canvas');
          canvas.width = 512;
          canvas.height = 512;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, offsetX, offsetY, size, size, 0, 0, 512, 512);
          selectedAvatar = canvas.toDataURL('image/png');
          avatarImg.src = selectedAvatar;
          document.querySelectorAll('.secra-avatar-option').forEach(el => el.classList.remove('selected'));
          avatarImg.classList.add('selected');
        };
        img.src = event.target.result;
      };
      reader.readAsDataURL(file);
    };

    const nicknameInput = createEl('input', { type: 'text', placeholder: 'Введите никнейм', maxlength: '20' });
    const createBtn = createEl('button', { class: 'secra-btn' }, t('create_profile_btn'));
    const backBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('back'));

    const content = createEl('div', {}, [
      this._createStepIndicator(),
      createEl('h4', {}, t('create_profile')),
      createEl('p', {}, t('choose_avatar')),
      avatarGrid,
      createEl('p', {}, t('enter_nickname')),
      nicknameInput,
      createEl('div', {}, [backBtn, createBtn])
    ]);

    createBtn.onclick = async () => {
      const nickname = nicknameInput.value.trim();
      if (!nickname) { alert('Введите никнейм'); return; }

      this.creationData.avatar = selectedAvatar;
      this.creationData.nickname = nickname;

      // Generate wallet + sodium keypairs
      const { wallet, sodiumKeys } = await mnemonicToWallet(this.creationData.mnemonic, this.ethers, this.sodium);
      this.creationData.wallet = wallet;
      this.creationData.sodiumKeys = sodiumKeys;

      createBtn.innerHTML = '<span class="secra-loading"></span>Отправка данных...';
      createBtn.disabled = true;

      const serverResponse = await serverRequest(this.cfg.serverUrl + '/create', {
        avatar: selectedAvatar,
        nickname: nickname,
        address: wallet.address,
        publicKey: sodiumKeys.box.publicKey, // send signing pubkey
        boxPublicKey: sodiumKeys.box.publicKey  // optional
      });

      if (serverResponse.success) {
        this.currentStep++;
        this._showCreateStep();
      } else {
        alert('Ошибка создания ID на сервере: ' + (serverResponse.error || 'Unknown error'));
        createBtn.innerHTML = t('create_profile_btn');
        createBtn.disabled = false;
      }
    };

    backBtn.onclick = () => { this.currentStep--; this._showCreateStep(); };

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Создание профиля', contentEl: content });
  };

  // Save encrypted private key to IndexedDB (preferred) and set metadata in localStorage
  async function saveEncryptedPrivateKeyToStorage(address, encryptedPrivateKey) {
    try {
      await idbPut(`priv:${address}`, encryptedPrivateKey);
      // keep a pointer or legacy copy (small) in localStorage if needed (not recommended to keep full plaintext)
      localStorage.setItem(KEYS.privEnc, 'idb-stored'); // mark that it's stored in idb
      return true;
    } catch (e) {
      console.warn('IDB store failed, falling back to localStorage', e);
      try { localStorage.setItem(KEYS.privEnc, encryptedPrivateKey); return true; } catch (err) { console.error('Both storage methods failed', err); return false; }
    }
  }

  SecraUI.prototype._setPinAndFinalize = function() {
    const pinInput = createEl('input', { type: 'password', placeholder: 'Введите 6-значный PIN', maxlength: '6' });
    const confirmPinInput = createEl('input', { type: 'password', placeholder: 'Подтвердите PIN', maxlength: '6' });
    const setPinBtn = createEl('button', { class: 'secra-btn' }, t('set_pin'));
    const backBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('back'));

    const content = createEl('div', {}, [
      this._createStepIndicator(),
      createEl('p', {}, t('enter_pin_security')),
      pinInput,
      confirmPinInput,
      createEl('div', {}, [backBtn, setPinBtn])
    ]);

    setPinBtn.onclick = async () => {
      const pin = pinInput.value;
      const confirmPin = confirmPinInput.value;
      if (!pin || pin.length !== 6) { alert('PIN должен содержать 6 цифр'); return; }
      if (pin !== confirmPin) { alert('PIN не совпадают'); return; }

      try {
        setPinBtn.innerHTML = '<span class="secra-loading"></span>Сохранение...';
        setPinBtn.disabled = true;

        const { wallet, avatar, nickname, sodiumKeys } = this.creationData;

        // Hash PIN
        const pinHash = await sha256Hex(pin);

        // Encrypt private key (wallet.privateKey) using derived key from PIN
        const salt = 'secra-salt:' + wallet.address;
        const aesKey = await deriveKeyFromPin(pin, salt);
        const encryptedPrivateKey = await encryptWithKey(aesKey, wallet.privateKey);

        // ALSO encrypt libsodium private keys and store them (optional)
        const encryptedSodiumSign = await encryptWithKey(aesKey, sodiumKeys.sign.privateKey);
        const encryptedSodiumBox = await encryptWithKey(aesKey, sodiumKeys.box.privateKey);

        // Save encrypted keys into IDB
        await saveEncryptedPrivateKeyToStorage(wallet.address, encryptedPrivateKey);
        await idbPut(`sodium_sign:${wallet.address}`, encryptedSodiumSign);
        await idbPut(`sodium_box:${wallet.address}`, encryptedSodiumBox);

        // Compute data hash
        const dataHash = await computeDataHash(avatar, wallet.address, 'idb-stored', pinHash);
        this.creationData.wallet = wallet;
        this.creationData.sodiumKeys = sodiumKeys;

        localStorage.setItem(`sodium_pub:${wallet.address}`, sodiumKeys.box.publicKey);
        console.log(sodiumKeys.box.publicKey);
        // Store metadata in localStorage
        localStorage.setItem(KEYS.avatar, avatar);
        localStorage.setItem(KEYS.name, nickname);
        localStorage.setItem(KEYS.address, wallet.address);
        localStorage.setItem(KEYS.pinHash, pinHash);
        localStorage.setItem(KEYS.dataHash, dataHash);

        // Generate identification data
        await this._generateIdentificationData(wallet.privateKey);

        // Show success
        this._showSuccess();

      } catch (error) {
        console.error('PIN setup error:', error);
        alert('PIN setup error');
        setPinBtn.innerHTML = t('set_pin');
        setPinBtn.disabled = false;
      }
    };

    backBtn.onclick = () => { this.currentStep--; this._showCreateStep(); };

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - PIN Setup', contentEl: content });
  };

  SecraUI.prototype._showSuccess = function() {
    const { avatar, nickname } = this.creationData;
    const forwardBtn = createEl('button', { class: 'secra-btn' }, t('forward'));
    const content = createEl('div', { style: 'text-align: center;' }, [
      createEl('h4', {}, t('id_created')),
      createEl('div', { style: 'margin: 20px 0;' }, [
        createEl('img', { src: avatar, alt: 'avatar', style: 'width: 80px; height: 80px; border-radius: 50%; margin-bottom: 10px;' }),
        createEl('p', {}, `<strong>${t('welcome_to_secra')}</strong>`),
        createEl('p', {}, nickname)
      ]),
      forwardBtn
    ]);

    forwardBtn.onclick = () => { window.location.href = this.cfg.redirectUrl; };

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Welcome!', contentEl: content, hideClose: true });
  };

  // Import flow
  SecraUI.prototype._startImportFlow = function() {
    const seedTextarea = createEl('textarea', { placeholder: 'Enter 12 or 24 words separated by spaces', rows: 4 });
    const importBtn = createEl('button', { class: 'secra-btn' }, t('import_btn'));
    const backBtn = createEl('button', { class: 'secra-btn secra-btn-secondary' }, t('back'));
    const content = createEl('div', {}, [ createEl('p', {}, t('enter_seed')), seedTextarea, createEl('div', {}, [backBtn, importBtn]) ]);

    importBtn.onclick = async () => {
      const seedPhrase = seedTextarea.value.trim();
      let words = seedPhrase.split(/\n|\s+/).map(w => w.replace(/^\d+\.\s*/, '')).filter(w => w.length > 0);
      if (words.length !== 12 && words.length !== 24) { alert('A mnemonic phrase should contain 12 or 24 words.'); return; }

      try {
        importBtn.innerHTML = '<span class="secra-loading"></span>' + t('checking_server');
        importBtn.disabled = true;

        const { wallet, sodiumKeys } = await mnemonicToWallet(words, this.ethers, this.sodium);

        const { challenge } = await serverRequest(this.cfg.serverUrl + '/check', { address: wallet.address, publicKey: sodiumKeys.sign.publicKey });

        const signature = await wallet.signMessage(challenge);

        const serverResponse = await serverRequest(this.cfg.serverUrl + '/verify', { address: wallet.address, signature });
        if (!serverResponse.success || !serverResponse.user) {
          alert(t('user_not_found'));
          importBtn.innerHTML = t('import_btn');
          importBtn.disabled = false;
          return;
        }

        const userData = serverResponse.user;
        localStorage.setItem("token", serverResponse.token);

        if (userData.address !== wallet.address) {
          alert(t('verification_failed'));
          importBtn.innerHTML = t('import_btn');
          importBtn.disabled = false;
          return;
        }

        // store wallet and sodiumKeys temporarily for next step
        this._setupImportPin({ wallet, sodiumKeys }, userData);

      } catch (error) {
        console.error('Import error:', error);
        alert('Import error: ' + error.message);
        importBtn.innerHTML = t('import_btn');
        importBtn.disabled = false;
      }
    };

    backBtn.onclick = () => this.openMainModal();

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Импорт ID', contentEl: content });
  };

  SecraUI.prototype._setupImportPin = function({ wallet, sodiumKeys }, userData) {
    const pinInput = createEl('input', { type: 'password', placeholder: 'Enter your 6-digit PIN', maxlength: '6' });
    const confirmPinInput = createEl('input', { type: 'password', placeholder: 'Confirm PIN', maxlength: '6' });
    const setPinBtn = createEl('button', { class: 'secra-btn' }, t('set_pin'));
    const content = createEl('div', {}, [
      createEl('p', {}, 'Set a PIN to protect the imported account'),
      pinInput,
      confirmPinInput,
      setPinBtn
    ]);

    setPinBtn.onclick = async () => {
      const pin = pinInput.value;
      const confirmPin = confirmPinInput.value;
      if (!pin || pin.length !== 6) { alert('The PIN must contain 6 digits.'); return; }
      if (pin !== confirmPin) { alert('PINs do not match'); return; }

      try {
        const pinHash = await sha256Hex(pin);
        const salt = 'secra-salt:' + wallet.address;
        const aesKey = await deriveKeyFromPin(pin, salt);
        const encryptedPrivateKey = await encryptWithKey(aesKey, wallet.privateKey);

        // also encrypt sodium private keys
        const encryptedSodiumSign = await encryptWithKey(aesKey, sodiumKeys.sign.privateKey);
        const encryptedSodiumBox = await encryptWithKey(aesKey, sodiumKeys.box.privateKey);

        // store encrypted into IDB
        await saveEncryptedPrivateKeyToStorage(wallet.address, encryptedPrivateKey);
        await idbPut(`sodium_sign:${wallet.address}`, encryptedSodiumSign);
        await idbPut(`sodium_box:${wallet.address}`, encryptedSodiumBox);
        localStorage.setItem(`sodium_pub:${wallet.address}`, sodiumKeys.box.publicKey);
        sessionStorage.setItem('Secra_private_unencrypted_temp', wallet.privateKey);

        const dataHash = await computeDataHash(userData.avatar, wallet.address, 'idb-stored', pinHash);
        console.log(sodiumKeys.box.publicKey);
        localStorage.setItem(KEYS.avatar, userData.avatar);
        localStorage.setItem(KEYS.name, userData.display_name);
        localStorage.setItem(KEYS.address, wallet.address);
        localStorage.setItem(KEYS.pinHash, pinHash);
        localStorage.setItem(KEYS.dataHash, dataHash);
        await this._generateIdentificationData(wallet.privateKey);
        this._showWelcomeBack(userData);

      } catch (error) {
        console.error('Import PIN setup error:', error);
        alert('PIN setup error');
      }
    };

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - PIN Setup', contentEl: content });
  };

  SecraUI.prototype._showWelcomeBack = function(userData) {
    const forwardBtn = createEl('button', { class: 'secra-btn' }, t('forward'));
    const content = createEl('div', { style: 'text-align: center;' }, [
      createEl('h4', {}, t('welcome_back')),
      createEl('div', { style: 'margin: 20px 0;' }, [
        createEl('img', { src: userData.avatar, alt: 'avatar', style: 'width: 80px; height: 80px; border-radius: 50%; margin-bottom: 10px;' }),
        createEl('p', {}, userData.name)
      ]),
      forwardBtn
    ]);

    forwardBtn.onclick = () => { window.location.href = this.cfg.redirectUrl; };

    if (this.currentModal) this.currentModal.closeModal();
    this.currentModal = showModal({ title: 'Secra - Welcome back!', contentEl: content, hideClose: true });
  };

  SecraUI.prototype._createStepIndicator = function() {
    const totalSteps = 6;
    const stepContainer = createEl('div', { class: 'secra-step-indicator' });
    for (let i = 0; i < totalSteps; i++) {
      const stepClass = i < this.currentStep ? 'secra-step completed' : i === this.currentStep ? 'secra-step active' : 'secra-step';
      stepContainer.appendChild(createEl('div', { class: stepClass }));
    }
    return stepContainer;
  };

  // --- Public helpers to access keys (safe) ---
  SecraUI.prototype.getEncryptedPrivateFromIDB = async function(address) {
    return await idbGet(`priv:${address}`);
  };

  SecraUI.prototype.getSodiumPrivateFromIDB = async function(address, which /* 'sign'|'box' */) {
    return await idbGet(`${which === 'box' ? 'sodium_box' : 'sodium_sign'}:${address}`);
  };

  SecraUI.prototype.deleteAccount = async function(address) {
    try {
      await idbDelete(`priv:${address}`);
      await idbDelete(`sodium_sign:${address}`);
      await idbDelete(`sodium_box:${address}`);
      localStorage.removeItem(KEYS.avatar);
      localStorage.removeItem(KEYS.name);
      localStorage.removeItem(KEYS.address);
      localStorage.removeItem(KEYS.pinHash);
      localStorage.removeItem(KEYS.dataHash);
      localStorage.removeItem(KEYS.privEnc);
      sessionStorage.removeItem('Secra_private_unencrypted_temp');
      return true;
    } catch (e) {
      console.error('deleteAccount failed', e);
      return false;
    }
  };

  // Export
  global.SecraUI = function(cfg) { return new SecraUI(cfg); };

})(window);
