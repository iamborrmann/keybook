/* ================================================================
   KeyBook — app.js
   Vanilla-JS Zugangsdaten-Manager.

   Aufbau (Module als Objekt-Namespaces innerhalb einer IIFE):
     Crypto       – PBKDF2-Keyableitung + AES-GCM Ver-/Entschlüsselung
     FileVault    – optionale Bindung an eine Tresor-Datei (Chromium)
     Store        – In-Memory-State + verschlüsselte Persistenz (localStorage)
     Groups       – CRUD für Gruppen
     Entries      – CRUD für Einträge
     Filters      – Such-/Filterlogik
     PasswordGen  – Passwortgenerator
     Clipboard    – Kopieren + visuelles Feedback
     PDF          – Druckansicht aufbauen + window.print()
     ImportExport – JSON-Export/-Import inkl. Validierung
     UI           – Rendering, Event-Binding, Modale, Toasts
     App          – Bootstrap / Unlock-Flow
   ================================================================ */

(function () {
  "use strict";

  /* Kurzschreibweise für DOM-Zugriff per ID */
  const $id = (id) => document.getElementById(id);

  /* ==============================================================
     ICONS — inline-SVG-Set (Outline, Feather-/Lucide-Stil)
     Offline-tauglich (kein CDN, file://-konform). Farbe folgt dem
     Theme über stroke="currentColor"; Größe folgt der font-size
     des Buttons (width/height = 1em). Strichstärke via CSS steuerbar.
     ============================================================== */
  const ICON_PATHS = {
    edit: '<path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>',
    print:
      '<polyline points="6 9 6 2 18 2 18 9"/>' +
      '<path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>' +
      '<rect x="6" y="14" width="12" height="8"/>',
    trash:
      '<polyline points="3 6 5 6 21 6"/>' +
      '<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>' +
      '<line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
    copy:
      '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
      '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    link:
      '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>' +
      '<polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    eyeOff:
      '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>' +
      '<line x1="1" y1="1" x2="23" y2="23"/>',
    chevronDown: '<polyline points="6 9 12 15 18 9"/>',
    chevronRight: '<polyline points="9 18 15 12 9 6"/>',
    sun:
      '<circle cx="12" cy="12" r="5"/>' +
      '<line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>' +
      '<line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>' +
      '<line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>' +
      '<line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
    moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  };
  /** Liefert das Inline-SVG-Markup für ein Icon (Name aus ICON_PATHS). */
  const Icons = {
    svg(name) {
      return (
        '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        (ICON_PATHS[name] || "") +
        "</svg>"
      );
    },
  };

  /* ==============================================================
     CRYPTO — AES-GCM-256 mit aus Master-Passwort abgeleitetem Key
     ============================================================== */
  const Crypto = {
    // Formatversion des verschlüsselten Blobs ({ v, iter, salt, iv, data }).
    // Wird mitgeschrieben, um künftige Formatänderungen unterscheiden zu können.
    BLOB_VERSION: 1,
    // Aktueller Richtwert (OWASP 2023 für PBKDF2-HMAC-SHA256).
    PBKDF2_ITERATIONS: 600000,
    // Fallback für Alt-Tresore, die noch ohne gespeicherte Iterationszahl existieren.
    LEGACY_ITERATIONS: 150000,
    // Obergrenze gegen manipulierte Dateien (riesige iter würde den Browser blockieren).
    MAX_ITERATIONS: 10000000,

    /**
     * Liest eine Iterationszahl aus einem (ggf. fremden) Blob robust ein:
     * ungültig/fehlend → Legacy-Wert, sonst nach oben gedeckelt. Die Zahl wird
     * NICHT angehoben, damit echte Tresore mit ihrem Originalwert entschlüsselbar
     * bleiben (das Anheben würde einen anderen Schlüssel ergeben).
     */
    clampIterations(value) {
      const n = Math.floor(Number(value));
      if (!Number.isFinite(n) || n <= 0) return this.LEGACY_ITERATIONS;
      return Math.min(n, this.MAX_ITERATIONS);
    },

    /** Leitet aus Passwort + Salt einen AES-GCM-Schlüssel ab. */
    async deriveKey(password, salt, iterations) {
      const enc = new TextEncoder();
      const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: iterations,
          hash: "SHA-256",
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    },

    /** Verschlüsselt ein JS-Objekt → { v, iter, salt, iv, data }. */
    async encrypt(obj, key, salt, iterations) {
      const enc = new TextEncoder();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = enc.encode(JSON.stringify(obj));
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        plaintext
      );
      return {
        v: this.BLOB_VERSION,
        iter: iterations,
        salt: this.toB64(salt),
        iv: this.toB64(iv),
        data: this.toB64(new Uint8Array(cipher)),
      };
    },

    /** Entschlüsselt einen Blob mit gegebenem Key. Wirft bei falschem Key. */
    async decrypt(blob, key) {
      const iv = this.fromB64(blob.iv);
      const data = this.fromB64(blob.data);
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
      );
      return JSON.parse(new TextDecoder().decode(plain));
    },

    /* base64-Helfer für ArrayBuffer/Uint8Array */
    toB64(bytes) {
      let bin = "";
      const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
      return btoa(bin);
    },
    fromB64(str) {
      const bin = atob(str);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    },
  };

  /* ==============================================================
     FILEVAULT — optionale Bindung des Tresors an eine Datei
     (File System Access API, nur Chromium-Browser).

     Reine I/O-Schicht: liest/schreibt den bereits verschlüsselten
     Blob und kennt weder Passwort noch Klartext. Das Datei-Handle
     liegt in IndexedDB (nicht JSON-serialisierbar, daher kein
     localStorage); der Dateiname zusätzlich als Klartext-Metadatum,
     damit der Lock-Screen den Zustand vor dem Entsperren kennt.
     ============================================================== */
  const FileVault = {
    META_KEY: "keybook.filelink", // { name } – nur Anzeige, kein Geheimnis
    DB_NAME: "keybook",
    STORE_NAME: "handles",
    HANDLE_KEY: "vault",

    handle: null,
    _tail: Promise.resolve(), // serialisiert Schreibvorgänge

    /** Unterstützt der Browser die File System Access API? */
    isSupported() {
      return typeof window.showOpenFilePicker === "function";
    },
    /** Ist zur Laufzeit ein Datei-Handle aktiv? */
    isLinked() {
      return !!this.handle;
    },
    /** Name der zuletzt verknüpften Datei (auch ohne aktives Handle). */
    linkedName() {
      try {
        const meta = JSON.parse(localStorage.getItem(this.META_KEY) || "null");
        return meta && meta.name ? String(meta.name) : null;
      } catch (e) {
        return null;
      }
    },

    /* ---------- IndexedDB (minimal, nur für das Handle) ---------- */
    _db() {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open(this.DB_NAME, 1);
        req.onupgradeneeded = () => req.result.createObjectStore(this.STORE_NAME);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    },
    async _idb(mode, fn) {
      const db = await this._db();
      try {
        return await new Promise((resolve, reject) => {
          const req = fn(db.transaction(this.STORE_NAME, mode).objectStore(this.STORE_NAME));
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
      } finally {
        db.close();
      }
    },

    /* ---------- Datei-Dialoge ---------- */
    _types() {
      return [{ description: "KeyBook-Tresor", accept: { "application/json": [".json"] } }];
    },
    /** Dialog: bestehende Tresor-Datei auswählen. */
    async pickExisting() {
      const [handle] = await window.showOpenFilePicker({ types: this._types() });
      return handle;
    },
    /** Dialog: Ort für eine neue Tresor-Datei wählen. */
    async pickNew() {
      return await window.showSaveFilePicker({
        types: this._types(),
        suggestedName: "keybook-tresor.json",
      });
    },

    /* ---------- Verknüpfung ---------- */
    /**
     * Prüft das Schreibrecht; fragt nur mit promptUser aktiv nach
     * (requestPermission verlangt eine User-Geste).
     */
    async ensurePermission(handle, promptUser) {
      const opts = { mode: "readwrite" };
      if ((await handle.queryPermission(opts)) === "granted") return true;
      if (!promptUser) return false;
      return (await handle.requestPermission(opts)) === "granted";
    },
    /** Verknüpft eine Datei dauerhaft (Handle + Metadatum sichern). */
    async link(handle) {
      if (!(await this.ensurePermission(handle, true)))
        throw new Error("Schreibzugriff auf die Datei wurde nicht erlaubt.");
      this.handle = handle;
      try {
        await this._idb("readwrite", (s) => s.put(handle, this.HANDLE_KEY));
        localStorage.setItem(this.META_KEY, JSON.stringify({ name: handle.name }));
      } catch (e) {
        // Ohne IndexedDB bleibt die Verknüpfung auf diese Sitzung beschränkt
        localStorage.removeItem(this.META_KEY);
      }
    },
    lostName: null, // Name einer nicht mehr nutzbaren Verknüpfung (nur Anzeige)

    /**
     * Bindet beim Start die zuletzt verknüpfte Datei wieder an.
     * Wirft nie: eine unbrauchbare Verknüpfung (Handle fehlt, ist beschädigt oder
     * die Rechteprüfung scheitert – z. B. nach einer Browser-Neuinstallation mit
     * erhaltenem Profil) wird als "lost" gemeldet und aufgeräumt. Sonst bliebe der
     * Lock-Screen leer, und ein halb gesetztes Handle ließe alle Speichervorgänge
     * (Setup, Wiederherstellung) an einer unerreichbaren Datei scheitern.
     * @returns {Promise<"linked"|"needs-permission"|"lost"|"none">}
     */
    async tryReconnect() {
      this.handle = null;
      if (!this.isSupported()) return "none";
      const name = this.linkedName();
      if (!name) return "none";
      let handle = null;
      let granted = false;
      try {
        handle = await this._idb("readonly", (s) => s.get(this.HANDLE_KEY));
        // Ohne User-Geste nur prüfen – nachgefragt wird erst per Button
        if (handle) granted = await this.ensurePermission(handle, false);
      } catch (e) {
        console.warn("Tresor-Datei: gemerkte Verknüpfung ist unbrauchbar.", e);
        handle = null;
      }
      if (!handle) {
        this.lostName = name;
        await this.unlink(); // verwaiste Verknüpfung entfernen – die Datei bleibt unberührt
        return "lost";
      }
      // Handle erst übernehmen, wenn es sich als nutzbar erwiesen hat
      this.handle = handle;
      return granted ? "linked" : "needs-permission";
    },
    /** Nachfragen nach Klick (User-Geste liegt vor). */
    async grantPermission() {
      return this.handle ? await this.ensurePermission(this.handle, true) : false;
    },
    /** Verknüpfung lösen – die Datei selbst bleibt unangetastet. */
    async unlink() {
      this.handle = null;
      try {
        localStorage.removeItem(this.META_KEY);
      } catch (e) {
        /* localStorage nicht verfügbar – es gibt nichts zu entfernen */
      }
      try {
        await this._idb("readwrite", (s) => s.delete(this.HANDLE_KEY));
      } catch (e) {
        /* Metadatum ist bereits entfernt – Verknüpfung gilt als gelöst */
      }
    },

    /* ---------- Lesen / Schreiben ---------- */
    /** Liest den Dateiinhalt als Text. */
    async read() {
      return await (await this.handle.getFile()).text();
    },
    /**
     * Schreibt Text in die Datei. Schreibvorgänge werden serialisiert, da pro
     * Handle nur ein Writable gleichzeitig offen sein darf. Ein Fehler bricht
     * die Kette nicht ab, wird aber an den Aufrufer weitergereicht (Fail-loud).
     */
    write(text) {
      const result = this._tail.then(() => this._writeNow(text));
      this._tail = result.catch(() => {});
      return result;
    },
    async _writeNow(text) {
      try {
        const w = await this.handle.createWritable();
        await w.write(text);
        await w.close();
      } catch (e) {
        // Browser-Meldungen sind englisch und technisch – verständlich übersetzen,
        // das Original für die Fehlersuche als cause anhängen.
        const err = new Error(this._writeMsg(e));
        err.cause = e;
        throw err;
      }
    },
    /** Übersetzt Schreibfehler des Browsers in eine verständliche Meldung. */
    _writeMsg(e) {
      if (e.name === "NotFoundError") return "Die Tresor-Datei wurde nicht gefunden.";
      if (e.name === "QuotaExceededError")
        return "Auf dem Ziellaufwerk ist kein Speicherplatz mehr frei.";
      return (
        "Die Tresor-Datei konnte nicht beschrieben werden " +
        "(schreibgeschützt, gesperrt oder Zugriff entzogen)."
      );
    },
  };

  /* ==============================================================
     STORE — hält State im Speicher und persistiert verschlüsselt
     ============================================================== */
  const Store = {
    KEY: "keybook.vault",
    state: { groups: [], entries: [] },
    cryptoKey: null, // abgeleiteter AES-Key (nur zur Laufzeit)
    salt: null,
    iterations: Crypto.PBKDF2_ITERATIONS, // KDF-Iterationen des aktuellen Tresors
    savedAt: null, // ISO-Zeitstempel des letzten Speicherns (Klartext-Metadatum)

    /** Gibt es bereits einen Tresor im localStorage? */
    exists() {
      return localStorage.getItem(this.KEY) !== null;
    },

    /** Liest den rohen verschlüsselten Blob. */
    readBlob() {
      const raw = localStorage.getItem(this.KEY);
      return raw ? JSON.parse(raw) : null;
    },

    /**
     * Neuen Tresor mit Master-Passwort anlegen.
     * @param {string} password
     * @param {{groups:Array,entries:Array}} [data] optionale Startdaten (z. B. aus Backup)
     */
    async create(password, data) {
      this.salt = crypto.getRandomValues(new Uint8Array(16));
      this.iterations = Crypto.PBKDF2_ITERATIONS;
      this.cryptoKey = await Crypto.deriveKey(password, this.salt, this.iterations);
      this.state = data
        ? { groups: data.groups || [], entries: data.entries || [] }
        : { groups: [], entries: [] };
      await this.persist();
    },

    /**
     * Entsperren: Passwort prüfen, State entschlüsseln.
     * @param {string} password
     * @param {object} [blob] Quelle; ohne Angabe aus localStorage
     */
    async unlock(password, blob) {
      blob = blob || this.readBlob();
      if (!blob) throw new Error("Kein Tresor vorhanden.");
      this.salt = Crypto.fromB64(blob.salt);
      // Iterationszahl aus dem Blob; Alt-Tresore ohne Wert nutzen den Legacy-Default,
      // riesige (manipulierte) Werte werden gegen DoS gedeckelt.
      const blobIter = Crypto.clampIterations(blob.iter);
      const key = await Crypto.deriveKey(password, this.salt, blobIter);
      // Wirft bei falschem Passwort (GCM-Authentifizierung schlägt fehl)
      const data = await Crypto.decrypt(blob, key);
      this.cryptoKey = key;
      this.iterations = blobIter;
      this.savedAt = blob.savedAt || null;
      this.state = {
        groups: Array.isArray(data.groups) ? data.groups : [],
        entries: Array.isArray(data.entries) ? data.entries : [],
      };
      // Alt-Tresor transparent auf aktuellen Iterations-Richtwert hochstufen.
      let needsPersist = false;
      if (this.iterations < Crypto.PBKDF2_ITERATIONS) {
        this.iterations = Crypto.PBKDF2_ITERATIONS;
        this.cryptoKey = await Crypto.deriveKey(password, this.salt, this.iterations);
        needsPersist = true;
      }
      // Schema-Migration der Einträge (einmalig, idempotent):
      const template = Entries.blank();
      this.state.entries.forEach((e) => {
        // Legacy-Bereinigungen VOR dem generischen Auffüllen, damit danach der
        // Default greift:
        // - altes Boolean-Flag googleAuth → authenticators-Array
        if ("googleAuth" in e) {
          e.authenticators = Entries.sanitizeAuthenticators(e);
          delete e.googleAuth;
          needsPersist = true;
        }
        // - pin war früher eine Checkbox (Boolean), ist jetzt ein Textfeld → Alt-Wert verwerfen
        if (typeof e.pin === "boolean") {
          delete e.pin;
          needsPersist = true;
        }
        // Neu hinzugekommene (oder soeben entfernte) Felder mit Default nachfüllen
        // (Datenkonsistenz bei Schema-Erweiterungen — verhindert undefined in
        // Formular/Anzeige).
        Object.keys(template).forEach((k) => {
          if (!(k in e)) {
            e[k] = Array.isArray(template[k]) ? [] : template[k];
            needsPersist = true;
          }
        });
      });
      if (needsPersist) {
        try {
          await this.persist();
        } catch (e) {
          // Passwort war korrekt – nur das Speichern scheiterte. Das muss die UI
          // anders melden als ein falsches Passwort.
          e.fileError = true;
          throw e;
        }
      }
    },

    /** Entsperren aus der verknüpften Tresor-Datei. */
    async unlockFromFile(password) {
      let blob;
      try {
        blob = JSON.parse(await FileVault.read());
      } catch (e) {
        const err = new Error("Tresor-Datei konnte nicht gelesen werden.");
        err.fileError = true; // erlaubt der UI eine passende Meldung
        throw err;
      }
      await this.unlock(password, blob);
    },

    /**
     * Prüft vor dem Schreiben, ob die Datei gefahrlos überschrieben werden darf.
     * Drei Fälle werden unterschieden:
     *  - Datei verschwunden (gelöscht/verschoben): Chrome würde sie über das
     *    gemerkte Handle stillschweigend neu anlegen → erst nach Rückfrage.
     *  - Datei vorhanden, aber unlesbar (Sperre, Cloud-Platzhalter): niemals
     *    blind überschreiben, sonst geht ein evtl. neuerer Stand verloren.
     *  - Fremde Änderung (z. B. zweiter Tab): Abgleich des Felds savedAt.
     * @returns {Promise<boolean>} false = Nutzer hat abgelehnt
     */
    async noConflict() {
      let text;
      try {
        text = await FileVault.read();
      } catch (e) {
        if (e.name === "NotFoundError")
          return this.onFileMissing ? await this.onFileMissing() : false;
        throw new Error("Die Tresor-Datei ist derzeit nicht lesbar.");
      }
      let fileStamp;
      try {
        fileStamp = JSON.parse(text).savedAt || null;
      } catch (e) {
        return true; // leere/unlesbare Struktur → Überschreiben ist der einzige Weg
      }
      if (!this.savedAt || fileStamp === this.savedAt) return true;
      return this.onFileConflict ? await this.onFileConflict(fileStamp) : false;
    },
    onFileConflict: null, // von der UI gesetzt; true = trotzdem überschreiben
    onFileMissing: null, // von der UI gesetzt; true = Datei neu anlegen

    /**
     * Verschlüsselt den aktuellen State und schreibt ihn weg.
     * Genau ein Ziel: im Datei-Modus ausschließlich die Datei (Fehler werden
     * weitergereicht → Fail-loud), sonst ausschließlich localStorage. Bewusst
     * keine Kopie im jeweils anderen Speicher — die bliebe beim Lösen der
     * Verknüpfung als unerwarteter (und evtl. veralteter) Zweitstand zurück.
     */
    async persist() {
      if (!this.cryptoKey) throw new Error("Tresor ist gesperrt.");
      const blob = await Crypto.encrypt(
        this.state,
        this.cryptoKey,
        this.salt,
        this.iterations
      );
      // Speicherzeitpunkt als Klartext-Metadatum (kein Geheimnis) mitschreiben
      blob.savedAt = new Date().toISOString();
      const json = JSON.stringify(blob);
      if (FileVault.isLinked()) {
        if (!(await this.noConflict()))
          throw new Error("Abgebrochen – die Datei wurde nicht überschrieben.");
        await FileVault.write(json);
      } else {
        localStorage.setItem(this.KEY, json);
      }
      this.savedAt = blob.savedAt;
    },

    /** Tresor komplett entfernen. */
    destroy() {
      localStorage.removeItem(this.KEY);
      this.state = { groups: [], entries: [] };
      this.cryptoKey = null;
      this.salt = null;
      this.iterations = Crypto.PBKDF2_ITERATIONS;
      this.savedAt = null;
    },

    /** State aus dem Speicher räumen (Sperren). */
    lock() {
      this.cryptoKey = null;
      this.salt = null;
      this.iterations = Crypto.PBKDF2_ITERATIONS;
      this.savedAt = null;
      this.state = { groups: [], entries: [] };
    },
  };

  /* ==============================================================
     GROUPS — CRUD für Gruppen
     ============================================================== */
  const Groups = {
    all() {
      return Store.state.groups;
    },
    get(id) {
      return Store.state.groups.find((g) => g.id === id) || null;
    },
    async add(name, color) {
      const group = { id: crypto.randomUUID(), name: name.trim(), color };
      Store.state.groups.push(group);
      await Store.persist();
      return group;
    },
    async update(id, name, color) {
      const g = this.get(id);
      if (!g) return;
      g.name = name.trim();
      g.color = color;
      await Store.persist();
    },
    /** Löscht eine Gruppe; betroffene Einträge verlieren die Zuordnung. */
    async remove(id) {
      Store.state.groups = Store.state.groups.filter((g) => g.id !== id);
      Store.state.entries.forEach((e) => {
        if (e.groupId === id) e.groupId = "";
      });
      await Store.persist();
    },
    /** Anzahl Einträge, die einer Gruppe zugeordnet sind. */
    countEntries(id) {
      return Store.state.entries.filter((e) => e.groupId === id).length;
    },
  };

  /* ==============================================================
     ENTRIES — CRUD für Zugangsdaten-Einträge
     ============================================================== */
  const Entries = {
    /** Kanonische Liste der unterstützten Authenticator-Apps (einzige Quelle der
     *  Wahrheit für Formular, Import-Validierung und Anzeige). Reihenfolge =
     *  Anzeige-Reihenfolge. */
    AUTHENTICATORS: [
      "Google Authenticator",
      "Microsoft Authenticator",
      "2FAS Authenticator",
      "Authy",
      "Aegis Authenticator",
      "Ente Auth",
      "Proton Authenticator",
      "Duo Mobile",
      "Yubico Authenticator",
      "Bitwarden Authenticator",
    ],
    /** Bereinigt/migriert das authenticators-Feld eines (roh eingelesenen) Eintrags.
     *  Idempotent: filtert gegen die kanonische Liste und hebt das alte Boolean-Feld
     *  `googleAuth` auf "Google Authenticator". Ergebnis folgt der kanonischen
     *  Reihenfolge und ist duplikatfrei. */
    sanitizeAuthenticators(src) {
      const present = new Set(
        Array.isArray(src.authenticators) ? src.authenticators : []
      );
      // Abwärtskompatibilität: altes googleAuth-Flag → Google Authenticator
      if (src.googleAuth === true) present.add("Google Authenticator");
      return this.AUTHENTICATORS.filter((a) => present.has(a));
    },
    /** Standard-Datensatz mit allen Feldern. */
    blank() {
      return {
        id: "",
        groupId: "",
        serviceName: "",
        serviceUrl: "",
        username: "",
        email: "",
        password: "",
        notes: "",
        paymentMethod: "",
        cost: "",
        paymentInterval: "",
        twoFA: false,
        authenticators: [],
        biometrics: false,
        passkey: false,
        passkeyInfo: "",
        pin: "",
        googleLinked: false,
        phone: "",
        recoveryPhone: "",
        recoveryEmail: "",
        securityQuestions: "",
        contractStart: "",
        contractEnd: "",
        cancellationPeriod: "",
        contractInfo: "",
        subscription: false,
      };
    },
    all() {
      return Store.state.entries;
    },
    get(id) {
      return Store.state.entries.find((e) => e.id === id) || null;
    },
    /** Anlegen (ohne id) oder Aktualisieren (mit id). */
    async save(data) {
      if (data.id) {
        const idx = Store.state.entries.findIndex((e) => e.id === data.id);
        if (idx !== -1) Store.state.entries[idx] = data;
      } else {
        data.id = crypto.randomUUID();
        Store.state.entries.push(data);
      }
      await Store.persist();
      return data;
    },
    async remove(id) {
      Store.state.entries = Store.state.entries.filter((e) => e.id !== id);
      await Store.persist();
    },
  };

  /* ==============================================================
     FILTERS — kombinierbare Such-/Filterlogik
     ============================================================== */
  const Filters = {
    search: "",
    groupId: "",
    onlySubscription: false,
    onlyAuthenticator: false,
    onlyBiometrics: false,
    onlyPin: false,
    onlyTwoFA: false,
    onlyPasskey: false,
    onlyGoogleLinked: false,

    apply(entries) {
      const q = this.search.trim().toLowerCase();
      return entries.filter((e) => {
        if (q && !(e.serviceName || "").toLowerCase().includes(q)) return false;
        if (this.groupId && e.groupId !== this.groupId) return false;
        if (this.onlySubscription && !e.subscription) return false;
        if (this.onlyAuthenticator && !(e.authenticators && e.authenticators.length)) return false;
        if (this.onlyBiometrics && !e.biometrics) return false;
        if (this.onlyPin && !(e.pin || "").trim()) return false;
        if (this.onlyTwoFA && !e.twoFA) return false;
        if (this.onlyPasskey && !e.passkey) return false;
        if (this.onlyGoogleLinked && !e.googleLinked) return false;
        return true;
      });
    },
    reset() {
      this.search = "";
      this.groupId = "";
      this.onlySubscription = false;
      this.onlyAuthenticator = false;
      this.onlyBiometrics = false;
      this.onlyPin = false;
      this.onlyTwoFA = false;
      this.onlyPasskey = false;
      this.onlyGoogleLinked = false;
    },
  };

  /* ==============================================================
     PASSWORD GENERATOR
     ============================================================== */
  const PasswordGen = {
    SETS: {
      upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      lower: "abcdefghijklmnopqrstuvwxyz",
      digits: "0123456789",
      symbols: "!@#$%^&*()-_=+[]{};:,.?/",
    },
    /** Erzeugt ein Passwort. opts: {length, upper, lower, digits, symbols}. */
    generate(opts) {
      let pool = "";
      const required = [];
      if (opts.upper) { pool += this.SETS.upper; required.push(this.SETS.upper); }
      if (opts.lower) { pool += this.SETS.lower; required.push(this.SETS.lower); }
      if (opts.digits) { pool += this.SETS.digits; required.push(this.SETS.digits); }
      if (opts.symbols) { pool += this.SETS.symbols; required.push(this.SETS.symbols); }
      if (!pool) throw new Error("Mindestens eine Zeichengruppe auswählen.");

      const len = Math.max(opts.length, required.length);
      const chars = [];
      // Mindestens ein Zeichen je gewählter Gruppe
      required.forEach((set) => chars.push(set[this.randInt(set.length)]));
      // Rest aus dem Gesamtpool auffüllen
      for (let i = chars.length; i < len; i++) {
        chars.push(pool[this.randInt(pool.length)]);
      }
      return this.shuffle(chars).join("");
    },
    /** Kryptografisch sichere Zufallszahl 0..max-1. */
    randInt(max) {
      const arr = new Uint32Array(1);
      // Rejection sampling für gleichverteilte Werte
      const limit = Math.floor(0xffffffff / max) * max;
      let v;
      do {
        crypto.getRandomValues(arr);
        v = arr[0];
      } while (v >= limit);
      return v % max;
    },
    /** Fisher-Yates-Shuffle mit sicherer Zufallsquelle. */
    shuffle(arr) {
      for (let i = arr.length - 1; i > 0; i--) {
        const j = this.randInt(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      return arr;
    },
    /** Erzeugt eine Passphrase. opts: {count, sep, capitalize, number}. */
    generatePassphrase(opts) {
      const words = [];
      for (let i = 0; i < opts.count; i++) {
        let w = this.WORDS[this.randInt(this.WORDS.length)].toLowerCase();
        if (opts.capitalize) w = w[0].toUpperCase() + w.slice(1);
        words.push(w);
      }
      let result = words.join(opts.sep);
      if (opts.number) result += opts.sep + this.randInt(100);
      return result;
    },
    WORDS: ("Aal Abend Acht Ader Adel Adler Affe Ahre Alge Alm Amsel Anker Apfel Arche Asche Ast Atem Auge Axt Bach Bahn Balken Band Bank Bann Bär Barsch Baum Beil Bein Berg Beute Biene Birke Birne Blatt Blei Blitz Blume Blüte Boden Bogen Boot Brücke Brunnen Buch Bug Bucht Burg Busch Dachs Dach Damm Dank Deich Diele Dorf Draht Drossel Duft Düne Ebene Eiche Eimer Eis Elch Elster Ente Erbe Erde Erle Esche Eule Falke Faden Falle Farn Farbe Fass Feld Fels Fest Feuer Fichte Fink Fisch Flamme Fleck Fluss Forst Frosch Fuchs Furt Gabe Gang Garten Gast Geist Gier Gipfel Glanz Glaube Gras Grat Grenze Grube Güte Gurt Gürtel Haar Hafen Haken Halm Hammer Hang Harfe Hase Hasel Helm Hirsch Höhle Holz Horn Hügel Hund Hütte Igel Insel Jade Jagd Jahr Jäger Joch Käfer Kahn Kamm Kante Karte Kette Kiefer Kiesel Kiste Klamm Klee Klang Kliff Krähe Kranich Krebs Kreuz Krug Kuckuck Küste Lachs Lanze Lärche Laube Lerche Licht Linde Loch Löwe Luchs Luft Lust Macht Marder Mast Mauer Meer Meise Möwe Moos Moor Mond Mund Münze Mut Nacht Nadel Nagel Narbe Nebel Neid Nest Netz Nische Ofen Öl Ort Otter Pacht Palme Panzer Park Pappel Pass Pfad Pfahl Pfau Pfeil Pferd Pilz Plan Platz Preis Probe Quelle Rabe Raps Rast Rauch Regen Reiher Riff Ried Ring Riss Röhre Rost Ruf Ruhe Rune Rust Saft Sand Salz Saum Schatz Schale Schilf Schnee Schnur Segel Seil Seele Senke Sichel Silber Sippe Sinn Sog Spatz Specht Sperling Spiegel Spross Stall Star Stamm Steg Stein Stern Storch Strand Strom Sturm Sucht Sumpf Sünde Tal Tanne Taube Teer Teich Tiger Tisch Torf Trank Traum Treue Trift Trog Tropf Truhe Tuch Turm Ufer Ulme Uhu Unke Urne Vogel Wabe Wacht Wal Wald Welle Wiese Wind Wolf Wort Wunsch Wust Zebra Zeche Zeit Zeuge Zinne Zweig Ziel Zwerg Alt Blass Blau Braun Bunt Derb Dicht Dünn Echt Edel Eng Fahl Fein Fest Flink Feucht Frisch Früh Glut Grau Grün Groß Gut Halt Hart Heiß Hell Herb Hoch Kalt Karg Klar Klein Klug Kurz Lang Laut Leer Leise Matt Mild Mutig Nah Nass Neu Öde Rein Reif Roh Rot Rund Sanft Satt Scharf Schmal Schön Schwach Schwarz Stark Steil Steif Still Stolz Süß Tief Treu Voll Warm Weiß Weit Wild Zäh Zart Angst Drang Freude Glück Groll Güte Kraft Laune Lust Mut Neid Reiz Ruhe Scham Sinn Tau Traum Trieb Wert Wille Wunsch Wut Zorn Span Staub Woge Hain Hecht Herd Greis Alp Bast Bengel Mähne Matsch Ohm Prunk Rübe Schoß Schuld Spange Staud Taub Tiefe Topf Tunke Tümpel Übel Wams").split(" "),
  };

  /* ==============================================================
     CLIPBOARD — Kopieren mit Fallback + visuellem Feedback
     ============================================================== */
  const Clipboard = {
    CLEAR_MS: 30000, // Zwischenablage nach 30 s automatisch leeren
    _timer: null,
    _last: null, // zuletzt von uns kopierter Wert (für gezieltes Leeren)

    async copy(text) {
      if (!text) return false;
      let ok = false;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
          ok = true;
        } else {
          ok = this.fallback(text);
        }
      } catch (e) {
        ok = this.fallback(text);
      }
      if (ok) this.scheduleClear(text);
      return ok;
    },

    /** Fallback über ein verstecktes Textarea (z. B. ältere Kontexte). */
    fallback(text) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      return ok;
    },

    /** Plant das Leeren der Zwischenablage; jede neue Kopie verschiebt den Timer. */
    scheduleClear(text) {
      this._last = text;
      if (this._timer) clearTimeout(this._timer);
      this._timer = setTimeout(() => this.clearIfUnchanged(text), this.CLEAR_MS);
    },

    /** Leert die Zwischenablage, sofern seither keine neuere Kopie erfolgte. */
    clearIfUnchanged(text) {
      this._timer = null;
      if (this._last !== text) return; // zwischenzeitlich etwas Neues kopiert
      this._last = null;
      this.wipe();
    },

    /** Sofort leeren (z. B. beim Sperren), nur wenn noch ein Wert von uns ansteht. */
    clearNow() {
      if (this._timer) { clearTimeout(this._timer); this._timer = null; }
      if (this._last !== null) {
        this._last = null;
        this.wipe();
      }
    },

    /** Versucht, die Zwischenablage zu leeren; bei fehlendem Fokus später erneut. */
    wipe() {
      const attempt = () => {
        if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
          return navigator.clipboard.writeText("").then(
            () => true,
            () => false
          );
        }
        // Fallback ohne Clipboard-API: Geheimnis mit einem Leerzeichen überschreiben.
        // (execCommand("copy") kann keinen komplett leeren Wert kopieren — ein
        //  einzelnes Leerzeichen entfernt das Geheimnis dennoch aus der Ablage.)
        return Promise.resolve(this.fallback(" "));
      };
      attempt().then((done) => {
        if (!done) {
          // Schreiben scheitert oft ohne Fokus → einmalig beim nächsten Fokus erneut versuchen
          window.addEventListener("focus", () => attempt(), { once: true });
        }
      });
    },
  };

  /* ==============================================================
     PDF — über Browser-Druckdialog (window.print + @media print)
     ============================================================== */
  const PDF = {
    NO_GROUP: "__none__",

    /** Druckt alle Einträge einer Gruppe. */
    printGroup(group, entries) {
      const name = group ? group.name : "Ohne Gruppe";
      const sorted = entries
        .slice()
        .sort((a, b) => (a.serviceName || "").localeCompare(b.serviceName || "", "de"));
      const html =
        `<h1 class="print-doc-title">${esc(name)}</h1>` +
        `<p class="print-doc-sub">KeyBook — ${sorted.length} Einträge — erstellt am ${this.today()}</p>` +
        this.table(sorted);
      this.render(html);
    },
    /** Druckt einen einzelnen Eintrag. */
    printEntry(entry) {
      const html =
        `<h1 class="print-doc-title">${esc(entry.serviceName) || "Eintrag"}</h1>` +
        `<p class="print-doc-sub">KeyBook — erstellt am ${this.today()}</p>` +
        this.table([entry]);
      this.render(html);
    },
    /** Druckt alle gefilterten Einträge als Tabelle, nach Gruppe gruppiert. */
    printAll(entries) {
      // Einträge nach Gruppen bündeln (wie in der Hauptansicht)
      const buckets = new Map(); // groupId -> Eintrags-Array
      entries.forEach((e) => {
        const gid = Groups.get(e.groupId) ? e.groupId : this.NO_GROUP;
        if (!buckets.has(gid)) buckets.set(gid, []);
        buckets.get(gid).push(e);
      });

      // Gruppenreihenfolge: alphabetisch nach Name, "Ohne Gruppe" zuletzt
      const order = Groups.all()
        .filter((g) => buckets.has(g.id))
        .sort((a, b) => a.name.localeCompare(b.name, "de"))
        .map((g) => g.id);
      if (buckets.has(this.NO_GROUP)) order.push(this.NO_GROUP);

      const sections = order
        .map((gid) => {
          const group = gid === this.NO_GROUP ? null : Groups.get(gid);
          const items = buckets
            .get(gid)
            .slice()
            .sort((a, b) =>
              (a.serviceName || "").localeCompare(b.serviceName || "", "de")
            );
          const title = group
            ? `<span class="print-group-dot" style="background:${esc(safeColor(group.color))}"></span>${esc(group.name)}`
            : "Ohne Gruppe";
          return `<h2 class="print-group-title">${title}</h2>` + this.table(items);
        })
        .join("");

      const html =
        `<h1 class="print-doc-title">Zugangsdaten-Sammlung</h1>` +
        `<p class="print-doc-sub">KeyBook — ${entries.length} Einträge — erstellt am ${this.today()}</p>` +
        (sections || "<p>Keine Einträge.</p>");
      this.render(html);
    },
    /** Baut eine Tabelle: Dienst, Username, E-Mail, Passwort, Notizen + Sicherheit. */
    table(entries) {
      const td = (v) => `<td>${esc(v || "")}</td>`;
      // Zeilenumbrüche der Notizen/Sicherheitsfragen im Druck erhalten.
      const nl2br = (v) => esc(v || "").replace(/\n/g, "<br>");
      // Notizen + kompakter Sicherheits-Block in einer Zelle.
      const notesCell = (e) => {
        const parts = [];
        if (e.notes) parts.push(`<div class="print-notes">${nl2br(e.notes)}</div>`);
        // Positive Flags nur anzeigen, wenn aktiv (negative Werte weglassen).
        const flags = [];
        if (e.twoFA) flags.push("2FA: Ja");
        if (e.biometrics) flags.push("Biometrie: Ja");
        if (e.passkey) flags.push("Passkey: Ja");
        if (e.googleLinked) flags.push("Google verknüpft: Ja");
        const sec = [];
        if (flags.length) sec.push(flags.join(" · "));
        if (e.authenticators && e.authenticators.length)
          sec.push(`Authenticator: ${esc(e.authenticators.map((a) => a.replace(/\s*Authenticator$/, "")).join(", "))}`);
        if (e.passkeyInfo) sec.push(`Passkey-Details: ${esc(e.passkeyInfo)}`);
        if (e.pin) sec.push(`PIN: ${esc(e.pin)}`);
        if (e.phone) sec.push(`Telefon: ${esc(e.phone)}`);
        if (e.recoveryPhone)
          sec.push(`Wiederherstellungs-Telefon: ${esc(e.recoveryPhone)}`);
        if (e.recoveryEmail)
          sec.push(`Wiederherstellungs-E-Mail: ${esc(e.recoveryEmail)}`);
        if (e.securityQuestions)
          sec.push(`Sicherheitsfragen: ${nl2br(e.securityQuestions)}`);
        if (sec.length)
          parts.push(
            `<div class="print-sec">` +
              sec.map((l) => `<div>${l}</div>`).join("") +
              `</div>`
          );
        return `<td>${parts.join("")}</td>`;
      };
      const rows = entries
        .map(
          (e) =>
            `<tr>` +
            `<td class="print-td-name">${esc(e.serviceName || "")}</td>` +
            td(e.username) +
            td(e.email) +
            td(e.password) +
            notesCell(e) +
            `</tr>`
        )
        .join("");
      return (
        `<table class="print-table">` +
        `<thead><tr>` +
        `<th>Dienst</th><th>Username</th><th>E-Mail</th><th>Passwort</th><th>Notizen / Sicherheit</th>` +
        `</tr></thead>` +
        `<tbody>${rows}</tbody>` +
        `</table>`
      );
    },
    render(html) {
      const area = $id("print-area");
      area.innerHTML = html;
      const mql = window.matchMedia ? window.matchMedia("print") : null;
      let timer = null;
      let done = false;
      // Nach dem Druck Klartext-Inhalte wieder aus dem DOM entfernen.
      const clear = () => {
        if (done) return;
        done = true;
        area.innerHTML = "";
        window.removeEventListener("afterprint", clear);
        if (mql && mql.removeEventListener) mql.removeEventListener("change", onMql);
        if (timer) clearTimeout(timer);
      };
      // Verlassen des Druckmodus (Dialog geschlossen) → aufräumen.
      const onMql = (ev) => { if (!ev.matches) clear(); };
      window.addEventListener("afterprint", clear);
      if (mql && mql.addEventListener) mql.addEventListener("change", onMql);
      // Sicherheits-Fallback (lange genug, um NICHT in einen offenen Dialog zu leeren).
      timer = setTimeout(clear, 60000);
      window.print();
    },
    today() {
      return new Date().toLocaleDateString("de-DE");
    },
  };

  /* ==============================================================
     IMPORT / EXPORT — JSON
     ============================================================== */
  const ImportExport = {
    ENC_FORMAT: "keybook-encrypted",

    /** Löst den Download einer Textdatei aus. */
    download(text, filename) {
      const blob = new Blob([text], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },

    /** Klartext-Export aller Daten als JSON-Datei. */
    exportJSON() {
      const payload = {
        groups: Store.state.groups,
        entries: Store.state.entries,
      };
      this.download(
        JSON.stringify(payload, null, 2),
        `keybook-export-${this.stamp()}.json`
      );
    },

    /** Verschlüsselter Export – mit dem aktuellen Master-Schlüssel/Salt geschützt. */
    async exportEncrypted() {
      const payload = {
        groups: Store.state.groups,
        entries: Store.state.entries,
      };
      const blob = await Crypto.encrypt(
        payload,
        Store.cryptoKey,
        Store.salt,
        Store.iterations
      );
      blob.format = this.ENC_FORMAT;
      this.download(
        JSON.stringify(blob, null, 2),
        `keybook-export-verschluesselt-${this.stamp()}.json`
      );
    },

    /**
     * Erkennt eine verschlüsselte Datei an ihrer Struktur.
     * Der Format-Marker ist **optional**: Tresor-Dateien (aus `Store.persist()`)
     * tragen ihn nicht, sind aber im identischen Format verschlüsselt und sollen
     * sich ebenso wiederherstellen/importieren lassen — in Firefox/Safari ist das
     * sogar der einzige Weg, an eine Tresor-Datei zu kommen. Maßgeblich sind die
     * drei base64-Felder; ein Klartext-Backup besitzt sie nicht.
     */
    isEncrypted(data) {
      const knownFormats = [this.ENC_FORMAT, "accountmaster-encrypted"];
      return !!(
        data &&
        typeof data === "object" &&
        (data.format === undefined || knownFormats.includes(data.format)) &&
        typeof data.data === "string" &&
        typeof data.salt === "string" &&
        typeof data.iv === "string"
      );
    },

    /** Entschlüsselt eine verschlüsselte Exportdatei mit dem gegebenen Passwort. */
    async decryptImport(blob, password) {
      const salt = Crypto.fromB64(blob.salt);
      const iter = Crypto.clampIterations(blob.iter);
      const key = await Crypto.deriveKey(password, salt, iter);
      // Wirft bei falschem Passwort (GCM-Auth-Tag schlägt fehl)
      return await Crypto.decrypt(blob, key);
    },

    stamp() {
      const d = new Date();
      const p = (n) => String(n).padStart(2, "0");
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
    },
    /** Validiert die importierte Struktur. Wirft bei Fehlern. */
    validate(data) {
      if (typeof data !== "object" || data === null)
        throw new Error("Datei enthält kein gültiges JSON-Objekt.");
      if (!Array.isArray(data.groups))
        throw new Error('Feld "groups" fehlt oder ist kein Array.');
      if (!Array.isArray(data.entries))
        throw new Error('Feld "entries" fehlt oder ist kein Array.');
      data.groups.forEach((g, i) => {
        if (!g || typeof g.name !== "string")
          throw new Error(`Gruppe #${i + 1} ist ungültig (kein Name).`);
      });
      data.entries.forEach((e, i) => {
        if (!e || typeof e.serviceName !== "string")
          throw new Error(`Eintrag #${i + 1} ist ungültig (kein Dienstname).`);
      });
      return true;
    },
    /** Normalisiert importierte Datensätze auf das vollständige Schema. */
    normalize(data) {
      const groups = data.groups.map((g) => ({
        id: g.id || crypto.randomUUID(),
        name: String(g.name),
        // Nur gültige Hex-Farben übernehmen (verhindert CSS-Injection via Import)
        color: isHexColor(g.color) ? g.color : "#97a39d",
      }));
      const str = (v) => (v == null ? "" : String(v));
      const entries = data.entries.map((e) => {
        const src = e && typeof e === "object" ? e : {};
        // Nur die bekannten Felder aus Entries.blank() übernehmen — kein
        // Object.assign, damit weder Fremdfelder noch __proto__ aus der Datei
        // in den Tresor gelangen (Prototype-Pollution/Datenwildwuchs vermeiden).
        const out = Entries.blank();
        Object.keys(out).forEach((k) => {
          if (k === "authenticators") {
            // Array gegen die kanonische Liste filtern + Legacy googleAuth migrieren
            out[k] = Entries.sanitizeAuthenticators(src);
          } else {
            out[k] = typeof out[k] === "boolean" ? !!src[k] : str(src[k]);
          }
        });
        out.id = typeof src.id === "string" && src.id ? src.id : crypto.randomUUID();
        return out;
      });
      return { groups, entries };
    },
    /** Ersetzt den gesamten State. */
    async replace(data) {
      const norm = this.normalize(data);
      Store.state.groups = norm.groups;
      Store.state.entries = norm.entries;
      await Store.persist();
    },
    /** Ergänzt bestehende Daten (IDs werden neu vergeben, um Kollisionen zu vermeiden). */
    async merge(data) {
      const norm = this.normalize(data);
      // Bestehende Gruppennamen → ID-Map zur Wiederverwendung
      const byName = new Map(Store.state.groups.map((g) => [g.name.toLowerCase(), g.id]));
      const idMap = new Map(); // alte importierte ID → finale ID

      norm.groups.forEach((g) => {
        const existing = byName.get(g.name.toLowerCase());
        if (existing) {
          idMap.set(g.id, existing);
        } else {
          const newId = crypto.randomUUID();
          idMap.set(g.id, newId);
          Store.state.groups.push({ id: newId, name: g.name, color: g.color });
          byName.set(g.name.toLowerCase(), newId);
        }
      });

      norm.entries.forEach((e) => {
        e.id = crypto.randomUUID();
        if (e.groupId && idMap.has(e.groupId)) e.groupId = idMap.get(e.groupId);
        else if (e.groupId && !Groups.get(e.groupId)) e.groupId = "";
        Store.state.entries.push(e);
      });

      await Store.persist();
    },
  };

  /* ==============================================================
     THEME — Hell/Dunkel-Umschaltung (Einstellung in localStorage)
     ============================================================== */
  const Theme = {
    KEY: "keybook.theme",

    /** Liest die gespeicherte Einstellung und wendet sie an. */
    init() {
      const saved = localStorage.getItem(this.KEY); // "dark" | "light" | null
      const prefersDark =
        window.matchMedia &&
        window.matchMedia("(prefers-color-scheme: dark)").matches;
      this.apply(saved || (prefersDark ? "dark" : "light"));
    },

    current() {
      return document.documentElement.getAttribute("data-theme") === "dark"
        ? "dark"
        : "light";
    },

    /** Setzt das Theme auf html[data-theme] und aktualisiert das Icon. */
    apply(mode) {
      document.documentElement.setAttribute("data-theme", mode);
      const btn = $id("btn-theme");
      if (btn) {
        btn.innerHTML = mode === "dark" ? Icons.svg("sun") : Icons.svg("moon");
        btn.title = mode === "dark" ? "Hellen Modus aktivieren" : "Dunklen Modus aktivieren";
      }
    },

    /** Wechselt das Theme und speichert die Wahl. */
    toggle() {
      const next = this.current() === "dark" ? "light" : "dark";
      this.apply(next);
      localStorage.setItem(this.KEY, next);
    },
  };

  /* ==============================================================
     IDLE-LOCK — sperrt den Tresor automatisch bei Inaktivität
     ============================================================== */
  const IdleLock = {
    TIMEOUT_MS: 2 * 60 * 1000, // 2 Minuten ohne Aktivität
    EVENTS: ["mousedown", "mousemove", "keydown", "touchstart", "scroll", "wheel"],
    WARN_SECONDS: 30, // Countdown ab hier hervorheben
    _timer: null,
    _tick: null, // Intervall für die Countdown-Anzeige
    _deadline: null, // Zeitpunkt (ms) der geplanten Sperre
    _onActivity: null,

    /** Startet die Überwachung (nach erfolgreichem Entsperren). */
    start() {
      if (!this._onActivity) {
        this._onActivity = () => this.reset();
        this.EVENTS.forEach((ev) =>
          document.addEventListener(ev, this._onActivity, { passive: true })
        );
      }
      this.reset();
      if (!this._tick) this._tick = setInterval(() => this.render(), 1000);
    },

    /** Setzt den Inaktivitäts-Timer zurück. */
    reset() {
      if (this._timer) clearTimeout(this._timer);
      this._deadline = Date.now() + this.TIMEOUT_MS;
      this._timer = setTimeout(() => this.onIdle(), this.TIMEOUT_MS);
      this.render();
    },

    /** Stoppt die Überwachung (beim Sperren). */
    stop() {
      if (this._timer) { clearTimeout(this._timer); this._timer = null; }
      if (this._tick) { clearInterval(this._tick); this._tick = null; }
      this._deadline = null;
      if (this._onActivity) {
        this.EVENTS.forEach((ev) =>
          document.removeEventListener(ev, this._onActivity)
        );
        this._onActivity = null;
      }
      this.render();
    },

    /**
     * Aktualisiert die Countdown-Anzeige im Header (m:ss). Rechnet vom Zeitpunkt
     * der Sperre aus statt mitzuzählen — bleibt so auch bei gedrosselten Timern
     * (Hintergrund-Tab) korrekt.
     */
    render() {
      const val = $id("idle-timer-value");
      if (!val) return;
      const ms = this._deadline ? Math.max(0, this._deadline - Date.now()) : this.TIMEOUT_MS;
      const s = Math.ceil(ms / 1000);
      const text = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
      if (val.textContent !== text) val.textContent = text; // mousemove feuert oft
      $id("idle-timer").classList.toggle("warn", !!this._deadline && s <= this.WARN_SECONDS);
    },

    /** Wird bei Inaktivität ausgelöst: sperrt, falls noch entsperrt. */
    onIdle() {
      this._timer = null;
      if (Store.cryptoKey) {
        App.lock("Automatisch gesperrt wegen Inaktivität.");
      }
    },
  };

  /* ==============================================================
     UI — Rendering, Modale, Events, Toasts
     ============================================================== */
  const UI = {
    // Zustand für ausstehende Bestätigungsaktion
    confirmCallback: null,
    pendingImport: null, // validierte Importdaten
    encryptedImportBlob: null, // verschlüsselte Datei, die auf ein Passwort wartet

    init() {
      this.bindHeader();
      this.bindFilters();
      this.bindEntryModal();
      this.bindGenerator();
      this.bindGroups();
      this.bindImport();
      this.bindConfirm();
      this.bindGlobalClose();
      this.bindExport();
      this.bindPasswordToggles();
      this.trackTopbarHeight();
    },

    /* ---------- Passwortfelder mit Auge (Klartext umschalten) ---------- */
    /** Verdrahtet alle .pw-toggle-Knöpfe; das Feld ist jeweils das vorige Geschwister. */
    bindPasswordToggles() {
      document.querySelectorAll(".pw-toggle").forEach((btn) => {
        this.setPwVisible(btn, false);
        btn.addEventListener("click", () => {
          const input = btn.previousElementSibling;
          this.setPwVisible(btn, input.type === "password");
          input.focus();
        });
      });
    },
    /** Schaltet ein Feld (über seinen Auge-Knopf) sichtbar/verborgen und pflegt Icon + ARIA. */
    setPwVisible(btn, visible) {
      btn.previousElementSibling.type = visible ? "text" : "password";
      btn.innerHTML = Icons.svg(visible ? "eyeOff" : "eye");
      btn.title = visible ? "Passwort verbergen" : "Passwort anzeigen";
      btn.setAttribute("aria-label", btn.title);
      btn.setAttribute("aria-pressed", String(visible));
    },
    /** Alle Felder unter root wieder verbergen – kein Klartext bleibt sichtbar stehen. */
    resetPasswordToggles(root = document) {
      root.querySelectorAll(".pw-toggle").forEach((btn) => this.setPwVisible(btn, false));
    },

    /** Schreibt die echte Höhe der fixierten Topbar (Header + ggf. offene
        Filterleiste) laufend in --topbar-h. Daran richten sich der sticky
        Tabellenkopf und die Info-Card aus, damit nichts verdeckt wird. */
    trackTopbarHeight() {
      const topbar = document.querySelector(".topbar");
      if (!topbar) return;
      const sync = () =>
        document.documentElement.style.setProperty("--topbar-h", topbar.offsetHeight + "px");
      sync();
      if (window.ResizeObserver) new ResizeObserver(sync).observe(topbar);
      else window.addEventListener("resize", sync);
    },

    /* ---------- Export (Auswahl verschlüsselt / Klartext) ---------- */
    bindExport() {
      $id("btn-export-encrypted").addEventListener("click", async () => {
        try {
          await ImportExport.exportEncrypted();
          this.closeModal("export-modal");
          this.toast("Verschlüsselter Export erstellt ✓", "success");
        } catch (e) {
          this.toast("Export fehlgeschlagen: " + e.message, "error", 5000);
        }
      });
      $id("btn-export-plaintext").addEventListener("click", () => {
        this.closeModal("export-modal");
        this.openConfirm(
          "Export im Klartext",
          "Achtung: Die Datei enthält ALLE Daten inklusive Passwörter " +
            "unverschlüsselt im Klartext. Sicher aufbewahren und nach Gebrauch löschen. " +
            "Trotzdem als Klartext exportieren?",
          () => {
            ImportExport.exportJSON();
            this.toast("Klartext-Export erstellt ✓", "success");
          },
          { okLabel: "Klartext exportieren", danger: false }
        );
      });
    },

    /* ---------- Rendering ---------- */
    renderAll() {
      this.renderFilterGroupOptions();
      this.renderEntryGroupOptions();
      this.renderList();
    },

    // Liste-Zustand: zugeklappte Gruppen + aktuell ausgewählter Eintrag
    collapsedGroups: new Set(), // enthält Gruppen-IDs bzw. "__none__"
    selectedId: null,
    passwordsHidden: true,
    NO_GROUP: "__none__",

    /** Baut die nach Gruppen gegliederte, auf-/zuklappbare Liste auf. */
    renderList() {
      const list = $id("entry-list");
      const empty = $id("empty-state");
      const tableWrap = document.querySelector(".table-wrap");
      const entries = Filters.apply(Entries.all());

      this.updateVaultDate(); // „Tresor vom …" aktuell halten

      list.innerHTML = "";

      if (entries.length === 0) {
        empty.hidden = false;
        tableWrap.hidden = true;
        // Keine sichtbaren Einträge → Info-Card leeren. Bewusst ohne Prüfung auf
        // selectedId: die kann bereits anderweitig genullt worden sein (z. B. in
        // App.lock()), während die Card noch das alte Markup enthält.
        this.renderInfoCard(null);
        return;
      }
      empty.hidden = true;
      tableWrap.hidden = false;

      // Einträge nach Gruppen bündeln
      const buckets = new Map(); // groupId -> Eintrags-Array
      entries.forEach((e) => {
        const gid = Groups.get(e.groupId) ? e.groupId : this.NO_GROUP;
        if (!buckets.has(gid)) buckets.set(gid, []);
        buckets.get(gid).push(e);
      });

      // Gruppenreihenfolge: alphabetisch nach Name, "Ohne Gruppe" zuletzt
      const order = Groups.all()
        .filter((g) => buckets.has(g.id))
        .sort((a, b) => a.name.localeCompare(b.name, "de"))
        .map((g) => g.id);
      if (buckets.has(this.NO_GROUP)) order.push(this.NO_GROUP);

      // Pro Gruppe: Kopfzeile + (falls aufgeklappt) Eintragszeilen
      order.forEach((gid) => {
        const group = gid === this.NO_GROUP ? null : Groups.get(gid);
        const items = buckets
          .get(gid)
          .slice()
          .sort((a, b) =>
            (a.serviceName || "").localeCompare(b.serviceName || "", "de")
          );
        const collapsed = this.collapsedGroups.has(gid);

        list.appendChild(this.groupHeaderRow(gid, group, items.length, collapsed));
        if (!collapsed) items.forEach((e) => list.appendChild(this.entryRow(e, group)));
      });

      // Auswahl-Highlight wiederherstellen / Card aktualisieren
      if (this.selectedId && entries.some((e) => e.id === this.selectedId)) {
        this.highlightSelected();
      } else {
        this.renderInfoCard(null); // nichts (mehr) ausgewählt → Card leeren
      }

      // Collapse-All-Button anpassen
      const colBtn = $id("btn-collapse-all");
      if (colBtn) {
        const gids = [...new Set(
          entries.map((e) => (Groups.get(e.groupId) ? e.groupId : this.NO_GROUP))
        )];
        const allCollapsed = gids.length > 0 && gids.every((id) => this.collapsedGroups.has(id));
        colBtn.innerHTML = allCollapsed ? Icons.svg("chevronRight") : Icons.svg("chevronDown");
        colBtn.title = allCollapsed ? "Alle Gruppen aufklappen" : "Alle Gruppen zuklappen";
        colBtn.setAttribute("aria-label", colBtn.title);
      }
    },

    /** Farbige, klickbare Gruppen-Kopfzeile (auf-/zuklappbar). */
    groupHeaderRow(gid, group, count, collapsed) {
      const color = safeColor(group ? group.color : null);
      const name = group ? group.name : "Ohne Gruppe";

      const tr = document.createElement("tr");
      tr.className = "group-header-row";
      const td = document.createElement("td");
      td.colSpan = 5;
      td.className = "group-header-cell";
      td.style.borderLeft = `4px solid ${color}`;
      td.style.background = hexToRgba(color, 0.15);
      td.innerHTML =
        `<button class="group-toggle" aria-expanded="${!collapsed}">` +
        `<span class="group-caret">${collapsed ? Icons.svg("chevronRight") : Icons.svg("chevronDown")}</span>` +
        `<span class="group-dot" style="background:${esc(color)}"></span>` +
        `<span class="group-name">${esc(name)}</span>` +
        `</button>` +
        `<button class="group-pdf-btn" title="Gruppe als PDF drucken" aria-label="Gruppe als PDF drucken">${Icons.svg("print")}</button>` +
        `<span class="group-count">${count}</span>`;
      td.querySelector(".group-toggle").addEventListener("click", () =>
        this.toggleGroup(gid)
      );
      td.querySelector(".group-pdf-btn").addEventListener("click", (ev) => {
        ev.stopPropagation();
        const group = gid === this.NO_GROUP ? null : Groups.get(gid);
        const items = Filters.apply(Entries.all()).filter(
          (e) => (Groups.get(e.groupId) ? e.groupId : this.NO_GROUP) === gid
        );
        PDF.printGroup(group, items);
      });
      tr.appendChild(td);
      return tr;
    },

    /** Klappt eine Gruppe auf/zu und rendert neu. */
    toggleGroup(gid) {
      if (this.collapsedGroups.has(gid)) this.collapsedGroups.delete(gid);
      else this.collapsedGroups.add(gid);
      this.renderList();
    },

    /** Klappt alle sichtbaren Gruppen auf einmal zu oder auf. */
    toggleAllGroups() {
      const entries = Filters.apply(Entries.all());
      const gids = new Set(
        entries.map((e) => (Groups.get(e.groupId) ? e.groupId : this.NO_GROUP))
      );
      const allCollapsed = [...gids].every((id) => this.collapsedGroups.has(id));
      if (allCollapsed) {
        gids.forEach((id) => this.collapsedGroups.delete(id));
      } else {
        gids.forEach((id) => this.collapsedGroups.add(id));
      }
      this.renderList();
    },

    /** Eine Eintragszeile (Dienst · Username · E-Mail · Passwort · Aktionen). */
    entryRow(e, group) {
      const row = document.createElement("tr");
      row.className = "entry-row";
      row.dataset.id = e.id;
      if (e.id === this.selectedId) row.classList.add("selected");
      // Farbiger linker Strich passend zur Gruppe
      row.style.boxShadow = `inset 3px 0 0 ${safeColor(group ? group.color : null, "#d1d5db")}`;

      // Zelle mit Wert + Kopier-Button (Button nur, wenn ein Wert da ist).
      // Flex-Container in einem inneren <div>, damit das <td> Tabellenzelle bleibt.
      const MASK = "••••••••";
      const copyCell = (value, maskable) => {
        if (!value) return '<span class="cell-empty">—</span>';
        const display = maskable && this.passwordsHidden ? MASK : esc(value);
        return (
          `<div class="copy-wrap"><span class="cell-val">${display}</span>` +
          `<button class="icon-btn row-copy" data-copyval="${esc(value)}" title="Kopieren" aria-label="Kopieren">${Icons.svg("copy")}</button></div>`
        );
      };

      const safeHref = safeUrl(e.serviceUrl);
      const linkIcon = safeHref
        ? `<a class="service-link-icon" href="${esc(safeHref)}" target="_blank" rel="noopener noreferrer" title="${esc(safeHref)}" aria-label="Link öffnen" tabindex="-1">${Icons.svg("link")}</a>`
        : "";
      const badges = (() => {
        const b = [];
        if (e.twoFA)        b.push('<span class="entry-badge badge-2fa">2FA</span>');
        if (e.authenticators && e.authenticators.length)
          b.push(`<span class="entry-badge badge-auth" title="${esc(e.authenticators.join(", "))}">Auth</span>`);
        if (e.googleLinked) b.push('<span class="entry-badge badge-google">Google</span>');
        if (e.subscription) b.push('<span class="entry-badge badge-abo">Abo</span>');
        // Zahlungsmethode dynamisch als Badge — beliebiger Text, einheitlicher Stil.
        const pm = (e.paymentMethod || "").trim();
        if (pm) b.push(`<span class="entry-badge badge-pay">${esc(pm)}</span>`);
        return b.join("");
      })();
      row.innerHTML =
        `<td class="cell-service"><div class="cell-service-inner">${linkIcon}${esc(e.serviceName)}${badges}</div></td>` +
        `<td class="cell-copy">${copyCell(e.username)}</td>` +
        `<td class="cell-copy">${copyCell(e.email)}</td>` +
        `<td class="cell-copy cell-pw">${copyCell(e.password, true)}</td>`;

      // Klick auf die Zeile wählt den Eintrag → Info-Card
      row.addEventListener("click", (ev) => {
        if (ev.target.closest("button")) return;
        this.selectEntry(e.id);
      });
      // Kopier-Buttons der Zeile (Username / E-Mail / Passwort)
      row.querySelectorAll(".row-copy").forEach((btn) => {
        btn.addEventListener("click", async (ev) => {
          ev.stopPropagation(); // Zeile nicht zusätzlich auswählen
          const ok = await Clipboard.copy(btn.getAttribute("data-copyval"));
          this.copyFeedback(btn, ok);
        });
      });
      return row;
    },

    /** Wählt einen Eintrag aus und zeigt ihn in der Info-Card. */
    selectEntry(id) {
      this.selectedId = id;
      this.highlightSelected();
      this.renderInfoCard(Entries.get(id));
    },

    /** Setzt die .selected-Markierung auf die passende Zeile. */
    highlightSelected() {
      document.querySelectorAll("#entry-list tr.entry-row").forEach((tr) => {
        tr.classList.toggle("selected", tr.dataset.id === this.selectedId);
      });
    },

    /** Rendert die Info-Card neu, falls der ausgewählte Eintrag noch existiert. */
    refreshSelectedCard() {
      if (this.selectedId && Entries.get(this.selectedId)) {
        this.renderInfoCard(Entries.get(this.selectedId));
      }
    },

    /** Rendert die Info-Card rechts mit ALLEN Feldern des Eintrags. */
    renderInfoCard(e) {
      const card = $id("info-card");
      card.className = "info-card layout-bar";

      if (!e) {
        this.selectedId = null;
        card.innerHTML =
          `<div class="info-empty"><span class="info-empty-icon">🗂️</span>` +
          `<p>Wähle links einen Eintrag aus,<br />um alle Details zu sehen.</p></div>`;
        return;
      }

      const group = Groups.get(e.groupId);
      const yn = (b) => (b ? "Ja" : "Nein");
      const fmtDate = (iso) => {
        if (!iso) return "";
        const d = new Date(iso + "T00:00:00");
        return isNaN(d) ? iso : d.toLocaleDateString("de-DE", { day: "numeric", month: "long", year: "numeric" });
      };

      // Einzelnes Info-Feld; opts: {copy, pre} (pre = Zeilenumbrüche erhalten).
      // Wert + Copy-Button stecken in .info-val-wrap, damit alle Layouts greifen.
      const MASK = "••••••••";
      const item = (label, value, opts) => {
        const o = opts || {};
        const empty = !value && value !== 0;
        const masked = o.mask && this.passwordsHidden && !empty;
        let valHtml;
        if (empty) {
          valHtml = '<span class="cell-empty">—</span>';
        } else if (masked) {
          valHtml = MASK;
        } else if (o.link) {
          // Nur unbedenkliche Schemata verlinken; sonst als reinen Text zeigen.
          const su = safeUrl(value);
          valHtml = su
            ? `<a href="${esc(su)}" target="_blank" rel="noopener noreferrer" class="info-link">${esc(value)}</a>`
            : esc(value);
        } else {
          valHtml = esc(value);
        }
        const valCls = "info-value" + (o.pre ? " pre" : "");
        const copyBtn =
          o.copy && !empty
            ? `<button class="icon-btn info-copy" data-copyval="${esc(value)}" title="Kopieren" aria-label="Kopieren">${Icons.svg("copy")}</button>`
            : "";
        return (
          `<div class="info-item"><span class="info-label">${label}</span>` +
          `<div class="info-val-wrap"><span class="${valCls}">${valHtml}</span>${copyBtn}</div></div>`
        );
      };

      // Eine Sektion (Box) mit Titel + Feld-Container
      const section = (title, fields) =>
        `<div class="info-section"><div class="info-section-title">${title}</div>` +
        `<div class="info-fields">${fields}</div></div>`;

      const badge = group
        ? `<span class="group-badge" style="background:${esc(safeColor(group.color))}">${esc(group.name)}</span>`
        : `<span class="group-badge no-group">Ohne Gruppe</span>`;

      card.innerHTML =
        `<div class="info-head">` +
        `<div class="info-head-main">` +
        `<h2 class="info-title">${esc(e.serviceName)}</h2>${badge}` +
        `</div>` +
        `<div class="info-head-actions">` +
        `<button class="icon-btn" data-action="edit" title="Bearbeiten" aria-label="Bearbeiten">${Icons.svg("edit")}</button>` +
        `<button class="icon-btn" data-action="pdf" title="PDF exportieren" aria-label="PDF exportieren">${Icons.svg("print")}</button>` +
        `<button class="icon-btn danger" data-action="delete" title="Löschen" aria-label="Löschen">${Icons.svg("trash")}</button>` +
        `</div></div>` +

        section(
          "Basisdaten",
          item("mit Google verknüpft", yn(e.googleLinked)) +
            item("Link", e.serviceUrl, { link: true }) +
            item("Username", e.username, { copy: true }) +
            item("Passwort", e.password, { copy: true, mask: true }) +
            item("E-Mail", e.email, { copy: true }) +
            item("Telefonnummer", e.phone, { copy: true }) +
            item("Notizen", e.notes, { pre: true })
        ) +

        section(
          "Sicherheit",
          item("Authenticator-App(s)", (e.authenticators || [])
              .map((a) => a.replace(/\s*Authenticator$/, "")).join(", ")) +
            item("2FA aktiviert", yn(e.twoFA)) +
            item("Biometrie", yn(e.biometrics)) +
            item("Passkey", yn(e.passkey)) +
            item("Passkey-Details", e.passkeyInfo) +
            item("PIN", e.pin) +
            item("Wiederherstellungs-Telefon", e.recoveryPhone, { copy: true }) +
            item("Wiederherstellungs-E-Mail", e.recoveryEmail, { copy: true }) +
            item("Sicherheitsfragen", e.securityQuestions, { pre: true })
        ) +

        section(
          "Vertrag / Abo",
          item("Abo aktiv", yn(e.subscription)) +
            item("Info", e.contractInfo) +
            item("Zahlungsmethode", e.paymentMethod) +
            item("Kosten", e.cost) +
            item("Zahlungsweise", e.paymentInterval) +
            item("Vertragsstart", fmtDate(e.contractStart)) +
            item("Vertragsende", fmtDate(e.contractEnd)) +
            item("Kündigungsfrist", e.cancellationPeriod)
        );

      // Aktionen in der Card
      card.querySelector('[data-action="edit"]').addEventListener("click", () =>
        this.openEntryModal(e.id)
      );
      card.querySelector('[data-action="pdf"]').addEventListener("click", () =>
        PDF.printEntry(e)
      );
      card.querySelector('[data-action="delete"]').addEventListener("click", () =>
        this.confirmDeleteEntry(e)
      );
      // Copy-Buttons
      card.querySelectorAll(".info-copy").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const ok = await Clipboard.copy(btn.getAttribute("data-copyval"));
          this.copyFeedback(btn, ok);
        });
      });
    },

    /** Füllt die Gruppen-Dropdowns (Filter + Eintragsformular). */
    renderFilterGroupOptions() {
      const sel = $id("filter-group");
      const current = sel.value;
      sel.innerHTML = '<option value="">Alle Gruppen</option>';
      Groups.all().sort((a, b) => a.name.localeCompare(b.name, "de")).forEach((g) => {
        const opt = document.createElement("option");
        opt.value = g.id;
        opt.textContent = g.name;
        sel.appendChild(opt);
      });
      sel.value = current; // Auswahl beibehalten, falls noch vorhanden
      if (sel.value !== current) Filters.groupId = sel.value;
    },
    renderEntryGroupOptions() {
      const sel = $id("entry-group");
      sel.innerHTML = '<option value="">— keine Gruppe —</option>';
      Groups.all().sort((a, b) => a.name.localeCompare(b.name, "de")).forEach((g) => {
        const opt = document.createElement("option");
        opt.value = g.id;
        opt.textContent = g.name;
        sel.appendChild(opt);
      });
    },

    /* ---------- Header ---------- */
    bindHeader() {
      $id("btn-new-entry").addEventListener("click", () => this.openEntryModal());
      $id("btn-toggle-filter").addEventListener("click", () => {
        const bar = $id("filter-bar");
        bar.hidden = !bar.hidden;
      });
      $id("btn-manage-groups").addEventListener("click", () => this.openGroupsModal());
      $id("btn-export-json").addEventListener("click", () => this.openModal("export-modal"));
      $id("btn-import-json").addEventListener("click", () => $id("import-file").click());
      $id("btn-export-pdf-all").addEventListener("click", () => this.openPrintModal());
      $id("btn-print-all-groups").addEventListener("click", () => this.setPrintSelection(true));
      $id("btn-print-no-groups").addEventListener("click", () => this.setPrintSelection(false));
      $id("btn-print-confirm").addEventListener("click", () => {
        const picked = this.selectedPrintGids();
        const items = Filters.apply(Entries.all()).filter((e) =>
          picked.has(Groups.get(e.groupId) ? e.groupId : this.NO_GROUP)
        );
        if (!items.length) return;
        this.closeModal("print-modal");
        PDF.printAll(items);
      });
      const pwBtn = $id("btn-pw-hide");
      const syncPwBtn = () => {
        pwBtn.classList.toggle("active", this.passwordsHidden);
        pwBtn.innerHTML = this.passwordsHidden ? Icons.svg("eyeOff") : Icons.svg("eye");
        pwBtn.title = this.passwordsHidden ? "Passwörter anzeigen" : "Passwörter verbergen";
        pwBtn.setAttribute("aria-label", pwBtn.title);
      };
      syncPwBtn();
      pwBtn.addEventListener("click", () => {
        this.passwordsHidden = !this.passwordsHidden;
        syncPwBtn();
        this.renderList();
        this.refreshSelectedCard();
      });
      $id("btn-collapse-all").addEventListener("click", () => this.toggleAllGroups());
      $id("btn-theme").addEventListener("click", () => Theme.toggle());
      $id("btn-help").addEventListener("click", () =>
        window.open("anleitung.html", "_blank", "noopener")
      );
      $id("btn-lock").addEventListener("click", () => App.lock());

      // Suche: Live-Filter + Lupe (abschicken/fokussieren) + Leeren-x
      const searchInput = $id("search-input");
      searchInput.addEventListener("input", (ev) => {
        Filters.search = ev.target.value;
        $id("search-clear").hidden = ev.target.value === "";
        this.renderList();
      });
      $id("search-submit").addEventListener("click", () => {
        Filters.search = searchInput.value;
        this.renderList();
        searchInput.focus();
      });
      $id("search-clear").addEventListener("click", () => this.clearSearch());
    },

    /** Leert das Suchfeld und setzt den Suchfilter zurück. */
    clearSearch() {
      $id("search-input").value = "";
      $id("search-clear").hidden = true;
      Filters.search = "";
      this.renderList();
      $id("search-input").focus();
    },

    /** Zeigt „Tresor vom <Datum>" anhand des letzten Speicherzeitpunkts. */
    updateVaultDate() {
      const el = $id("vault-date");
      if (!el) return;
      if (!Store.savedAt) {
        el.textContent = "";
        return;
      }
      const d = new Date(Store.savedAt);
      const datum = d.toLocaleDateString("de-DE");
      const zeit = d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
      el.textContent = `Tresor vom ${datum}, ${zeit} Uhr`;
    },

    /* ---------- Filter ---------- */
    bindFilters() {
      // Checkbox-Filter: [Element-ID, Filters-Flag] — Reihenfolge wie in der Leiste.
      const checkboxFilters = [
        ["filter-subscription", "onlySubscription"],
        ["filter-authenticator", "onlyAuthenticator"],
        ["filter-biometrics", "onlyBiometrics"],
        ["filter-pin", "onlyPin"],
        ["filter-twofa", "onlyTwoFA"],
        ["filter-passkey", "onlyPasskey"],
        ["filter-googlelinked", "onlyGoogleLinked"],
      ];
      $id("filter-group").addEventListener("change", (ev) => {
        Filters.groupId = ev.target.value;
        this.renderList();
      });
      checkboxFilters.forEach(([id, key]) => {
        $id(id).addEventListener("change", (ev) => {
          Filters[key] = ev.target.checked;
          this.renderList();
        });
      });
      $id("btn-clear-filters").addEventListener("click", () => {
        Filters.reset();
        $id("filter-group").value = "";
        checkboxFilters.forEach(([id]) => { $id(id).checked = false; });
        $id("search-input").value = "";
        $id("search-clear").hidden = true;
        this.renderList();
      });
    },

    /* ---------- Eintrags-Modal ---------- */
    bindEntryModal() {
      this.buildAuthenticatorOptions();
      $id("entry-form").addEventListener("submit", (ev) => {
        ev.preventDefault();
        this.saveEntryFromForm();
      });
      $id("btn-open-generator").addEventListener("click", () => this.openGenerator("entry"));
      $id("btn-header-generator").addEventListener("click", () => this.openGenerator(null));
      // Kosten beim Verlassen des Feldes automatisch mit „€" versehen
      $id("entry-cost").addEventListener("blur", (ev) => {
        ev.target.value = this.formatCost(ev.target.value);
      });
    },

    /** Hängt an einen nicht-leeren Kostenwert ein „€" an, falls noch keins enthalten. */
    formatCost(v) {
      v = (v || "").trim();
      if (v && !v.includes("€")) v += " €";
      return v;
    },

    /** Erzeugt die Authenticator-Checkboxen einmalig aus der kanonischen Liste. */
    buildAuthenticatorOptions() {
      $id("entry-authenticators").innerHTML = Entries.AUTHENTICATORS.map(
        (name) =>
          `<label><input type="checkbox" value="${esc(name)}" />` +
          `<span>${esc(name)}</span></label>`
      ).join("");
    },

    openEntryModal(id) {
      const data = id ? Entries.get(id) : Entries.blank();
      if (!data) return;
      $id("entry-modal-title").textContent = id ? "Eintrag bearbeiten" : "Neuer Eintrag";

      // Felder befüllen
      $id("entry-id").value = data.id;
      $id("entry-group").value = data.groupId || "";
      $id("entry-googleLinked").checked = data.googleLinked;
      $id("entry-serviceName").value = data.serviceName;
      $id("entry-serviceUrl").value = data.serviceUrl;
      $id("entry-username").value = data.username;
      $id("entry-password").value = data.password;
      $id("entry-email").value = data.email;
      $id("entry-phone").value = data.phone;
      $id("entry-notes").value = data.notes;
      $id("entry-twoFA").checked = data.twoFA;
      $id("entry-biometrics").checked = data.biometrics;
      $id("entry-passkey").checked = data.passkey;
      $id("entry-pin").value = data.pin;
      const activeAuth = new Set(data.authenticators || []);
      $id("entry-authenticators")
        .querySelectorAll('input[type="checkbox"]')
        .forEach((cb) => { cb.checked = activeAuth.has(cb.value); });
      $id("entry-passkeyInfo").value = data.passkeyInfo;
      $id("entry-recoveryPhone").value = data.recoveryPhone;
      $id("entry-recoveryEmail").value = data.recoveryEmail;
      $id("entry-securityQuestions").value = data.securityQuestions;
      $id("entry-paymentMethod").value = data.paymentMethod;
      $id("entry-cost").value = data.cost;
      $id("entry-paymentInterval").value = data.paymentInterval;
      $id("entry-subscription").checked = data.subscription;
      $id("entry-contractStart").value = data.contractStart;
      $id("entry-contractEnd").value = data.contractEnd;
      $id("entry-cancellationPeriod").value = data.cancellationPeriod;
      $id("entry-contractInfo").value = data.contractInfo;

      this.hideError("entry-error");
      this.openModal("entry-modal");
      $id("entry-serviceName").focus();
    },

    async saveEntryFromForm() {
      const serviceName = $id("entry-serviceName").value.trim();
      if (!serviceName) {
        this.showError("entry-error", "Bitte einen Dienstnamen angeben.");
        return;
      }
      // E-Mail-Syntax prüfen (leer erlaubt). Strikte Regel: lokaler Teil @ Domain
      // mit Punkt und TLD (mind. 2 Zeichen) — lehnt z. B. "a@b" oder "a@b." ab.
      const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
      const checkEmail = (inputId, label) => {
        const el = $id(inputId);
        const v = el.value.trim();
        if (v && !EMAIL_RE.test(v)) {
          this.showError("entry-error", `Bitte eine gültige ${label} eingeben.`);
          el.focus();
          return false;
        }
        return true;
      };
      if (!checkEmail("entry-email", "E-Mail-Adresse")) return;
      if (!checkEmail("entry-recoveryEmail", "Wiederherstellungs-E-Mail-Adresse")) return;
      // Kosten-Syntax prüfen (leer erlaubt): Zahl mit optionalen Tausender-/Dezimal-
      // trennern (Punkt, Komma, Leerzeichen); ein evtl. „€" wird ignoriert. Lehnt
      // z. B. "123-.,231" ab.
      const costRaw = $id("entry-cost").value.replace(/€/g, "").trim();
      if (costRaw && !/^\d+(?:[.,\s]\d+)*$/.test(costRaw)) {
        this.showError("entry-error", "Bitte einen gültigen Betrag bei „Kosten“ eingeben (z. B. 9,99).");
        $id("entry-cost").focus();
        return;
      }
      const data = {
        id: $id("entry-id").value,
        groupId: $id("entry-group").value,
        googleLinked: $id("entry-googleLinked").checked,
        serviceName: serviceName,
        serviceUrl: $id("entry-serviceUrl").value.trim(),
        username: $id("entry-username").value.trim(),
        email: $id("entry-email").value.trim(),
        password: $id("entry-password").value,
        notes: $id("entry-notes").value,
        paymentMethod: $id("entry-paymentMethod").value.trim(),
        cost: this.formatCost($id("entry-cost").value),
        paymentInterval: $id("entry-paymentInterval").value,
        twoFA: $id("entry-twoFA").checked,
        biometrics: $id("entry-biometrics").checked,
        passkey: $id("entry-passkey").checked,
        pin: $id("entry-pin").value.trim(),
        authenticators: Array.from(
          $id("entry-authenticators").querySelectorAll("input:checked")
        ).map((cb) => cb.value),
        passkeyInfo: $id("entry-passkeyInfo").value.trim(),
        phone: $id("entry-phone").value.trim(),
        recoveryPhone: $id("entry-recoveryPhone").value.trim(),
        recoveryEmail: $id("entry-recoveryEmail").value.trim(),
        securityQuestions: $id("entry-securityQuestions").value,
        contractStart: $id("entry-contractStart").value,
        contractEnd: $id("entry-contractEnd").value,
        cancellationPeriod: $id("entry-cancellationPeriod").value.trim(),
        contractInfo: $id("entry-contractInfo").value.trim(),
        subscription: $id("entry-subscription").checked,
      };
      if (!(await this.trySave(() => Entries.save(data), "entry-error"))) return;
      this.closeModal("entry-modal");
      this.renderList();
      this.refreshSelectedCard(); // Info-Card des bearbeiteten Eintrags aktualisieren
      this.toast("Eintrag gespeichert ✓", "success");
    },

    confirmDeleteEntry(entry) {
      this.openConfirm(
        "Eintrag löschen",
        `„${entry.serviceName}" wirklich löschen? Das kann nicht rückgängig gemacht werden.`,
        async () => {
          if (!(await this.trySave(() => Entries.remove(entry.id)))) return;
          this.renderList();
          this.toast("Eintrag gelöscht", "");
        }
      );
    },

    /* ---------- Passwortgenerator ---------- */
    genTarget: null, // Ziel des Übernehmen-Knopfs, s. openGenerator()
    bindGenerator() {
      ["pw", "pp"].forEach((mode) => {
        $id(`gen-tab-${mode}`).addEventListener("click", () => {
          $id("gen-tab-pw").classList.toggle("active", mode === "pw");
          $id("gen-tab-pp").classList.toggle("active", mode === "pp");
          $id("gen-panel-pw").hidden = mode !== "pw";
          $id("gen-panel-pp").hidden = mode !== "pp";
          this.runGenerator();
        });
      });
      const lengthInput = $id("gen-length");
      lengthInput.addEventListener("input", () => {
        $id("gen-length-value").textContent = lengthInput.value;
      });
      const wordsInput = $id("gen-words");
      wordsInput.addEventListener("input", () => {
        $id("gen-words-value").textContent = wordsInput.value;
      });
      $id("btn-generate").addEventListener("click", () => this.runGenerator());
      $id("btn-gen-copy").addEventListener("click", async (ev) => {
        const val = $id("gen-result").value;
        if (!val) return;
        const ok = await Clipboard.copy(val);
        this.copyFeedback(ev.target, ok);
      });
      $id("btn-gen-apply").addEventListener("click", () => {
        const val = $id("gen-result").value;
        if (!val) {
          this.showError("gen-error", "Erst ein Passwort generieren.");
          return;
        }
        if (this.genTarget === "master") {
          // Lock-Screen (Ersteinrichtung): beide Felder füllen und sichtbar schalten,
          // damit das neue Master-Passwort notiert werden kann.
          ["setup-password", "setup-password-repeat"].forEach((id) => {
            const input = $id(id);
            input.value = val;
            this.setPwVisible(input.nextElementSibling, true);
          });
          this.closeModal("generator-modal");
          this.hideError("setup-error");
          this.toast("Übernommen – bitte das Master-Passwort sicher notieren!", "success", 6000);
          return;
        }
        $id("entry-password").value = val;
        this.closeModal("generator-modal");
        this.toast("Passwort übernommen ✓", "success");
      });
    },
    /**
     * Öffnet den Generator. target bestimmt den Übernehmen-Knopf:
     * "entry" = ins Eintragsformular, "master" = als Master-Passwort (Lock-Screen,
     * Ersteinrichtung), null = nur Erzeugen/Kopieren.
     */
    openGenerator(target = null) {
      this.genTarget = target;
      const apply = $id("btn-gen-apply");
      apply.hidden = !target;
      apply.textContent =
        target === "master" ? "Als Master-Passwort übernehmen" : "In Eintrag übernehmen";
      this.hideError("gen-error");
      this.openModal("generator-modal");
      // Fürs Master-Passwort eine Passphrase vorschlagen (merkbarer); Tab bleibt umschaltbar.
      // Der Tab-Klick erzeugt selbst ein Ergebnis.
      if (target === "master") $id("gen-tab-pp").click();
      else this.runGenerator();
    },
    runGenerator() {
      this.hideError("gen-error");
      try {
        const isPassphrase = !$id("gen-panel-pp").hidden;
        let result;
        if (isPassphrase) {
          result = PasswordGen.generatePassphrase({
            count: parseInt($id("gen-words").value, 10),
            sep: $id("gen-pp-sep").value,
            capitalize: $id("gen-pp-upper").checked,
            number: $id("gen-pp-number").checked,
          });
        } else {
          result = PasswordGen.generate({
            length: parseInt($id("gen-length").value, 10),
            upper: $id("gen-upper").checked,
            lower: $id("gen-lower").checked,
            digits: $id("gen-digits").checked,
            symbols: $id("gen-symbols").checked,
          });
        }
        $id("gen-result").value = result;
      } catch (e) {
        this.showError("gen-error", e.message);
        $id("gen-result").value = "";
      }
    },

    /* ---------- Gruppenverwaltung ---------- */
    COLOR_PRESETS: [
      // Rosa (hell → mittel → dunkel)
      "#f8c8ce", "#f093a4", "#e05a72",
      // Pfirsich
      "#fdd9b5", "#f9ae72", "#f07a30",
      // Salbei
      "#b8e4c8", "#78c99a", "#4a9e72",
      // Lavendel
      "#c8d5f8", "#8aaae8", "#5b7ed8",
      // Grautöne
      "#d4d8dc", "#97a39d", "#6b7280", "#4b5563",
    ],
    bindGroups() {
      $id("group-form").addEventListener("submit", (ev) => {
        ev.preventDefault();
        this.saveGroupFromForm();
      });
      $id("group-cancel-btn").addEventListener("click", () => this.resetGroupForm());
      // Vordefinierte Farb-Swatches rendern
      const container = $id("color-presets");
      const GRAY_START = 12; // Index ab dem die Grautöne beginnen
      this.COLOR_PRESETS.forEach((color, i) => {
        if (i === GRAY_START) {
          const sep = document.createElement("span");
          sep.className = "color-preset-sep";
          container.appendChild(sep);
        }
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "color-preset";
        btn.style.background = color;
        btn.dataset.color = color;
        btn.title = color;
        btn.addEventListener("click", () => {
          $id("group-color").value = color;
          this.updatePresetSelection(color);
        });
        container.appendChild(btn);
      });
    },
    updatePresetSelection(color) {
      $id("color-presets").querySelectorAll(".color-preset").forEach((btn) => {
        btn.classList.toggle("selected", btn.dataset.color === color);
      });
    },
    /** Dialog: Gruppen für den Gesamtdruck wählen (Auswahl ∩ aktive Filter). */
    openPrintModal() {
      const items = Filters.apply(Entries.all());
      const counts = new Map(); // gid -> Trefferzahl
      items.forEach((e) => {
        const gid = Groups.get(e.groupId) ? e.groupId : this.NO_GROUP;
        counts.set(gid, (counts.get(gid) || 0) + 1);
      });
      // Reihenfolge wie im Druck: alphabetisch, "Ohne Gruppe" zuletzt
      const order = Groups.all()
        .filter((g) => counts.has(g.id))
        .sort((a, b) => a.name.localeCompare(b.name, "de"))
        .map((g) => g.id);
      if (counts.has(this.NO_GROUP)) order.push(this.NO_GROUP);

      const list = $id("print-group-list");
      list.innerHTML = "";
      if (!order.length) {
        list.innerHTML = '<li class="group-list-count">Keine Einträge zum Drucken.</li>';
      }
      order.forEach((gid) => {
        const g = gid === this.NO_GROUP ? null : Groups.get(gid);
        const color = safeColor(g ? g.color : null);
        const li = document.createElement("li");
        li.innerHTML =
          `<label class="print-group-item">` +
          `<input type="checkbox" checked />` +
          `<span class="group-dot" style="background:${esc(color)}"></span>` +
          `<span class="group-list-name">${esc(g ? g.name : "Ohne Gruppe")}</span>` +
          `<span class="group-list-count">${counts.get(gid)}</span>` +
          `</label>`;
        const cb = li.querySelector("input");
        cb.dataset.gid = gid;
        cb.dataset.count = counts.get(gid);
        cb.addEventListener("change", () => this.updatePrintSummary());
        list.appendChild(li);
      });
      this.updatePrintSummary();
      this.openModal("print-modal");
    },
    setPrintSelection(on) {
      $id("print-group-list").querySelectorAll("input[type=checkbox]").forEach((cb) => {
        cb.checked = on;
      });
      this.updatePrintSummary();
    },
    selectedPrintGids() {
      const set = new Set();
      $id("print-group-list").querySelectorAll("input[type=checkbox]:checked").forEach((cb) =>
        set.add(cb.dataset.gid)
      );
      return set;
    },
    updatePrintSummary() {
      let groups = 0;
      let count = 0;
      $id("print-group-list").querySelectorAll("input[type=checkbox]:checked").forEach((cb) => {
        groups++;
        count += Number(cb.dataset.count) || 0;
      });
      $id("print-summary").textContent = `${groups} Gruppen, ${count} Einträge ausgewählt`;
      $id("btn-print-confirm").disabled = count === 0;
    },
    openGroupsModal() {
      this.resetGroupForm();
      this.renderGroupList();
      this.openModal("groups-modal");
    },
    renderGroupList() {
      const list = $id("group-list");
      list.innerHTML = "";
      if (Groups.all().length === 0) {
        list.innerHTML = '<li class="group-list-count">Noch keine Gruppen angelegt.</li>';
        return;
      }
      Groups.all().sort((a, b) => a.name.localeCompare(b.name, "de")).forEach((g) => {
        const li = document.createElement("li");
        li.className = "group-list-item";
        li.innerHTML =
          `<span class="group-swatch" style="background:${esc(safeColor(g.color))}"></span>` +
          `<span class="group-list-name">${esc(g.name)}</span>` +
          `<span class="group-list-count">${Groups.countEntries(g.id)} Einträge</span>` +
          `<span class="group-list-actions">` +
          `<button class="icon-btn" data-action="edit" title="Bearbeiten" aria-label="Bearbeiten">${Icons.svg("edit")}</button>` +
          `<button class="icon-btn danger" data-action="delete" title="Löschen" aria-label="Löschen">${Icons.svg("trash")}</button>` +
          `</span>`;
        li.querySelector('[data-action="edit"]').addEventListener("click", () =>
          this.editGroup(g)
        );
        li.querySelector('[data-action="delete"]').addEventListener("click", () =>
          this.confirmDeleteGroup(g)
        );
        list.appendChild(li);
      });
    },
    editGroup(g) {
      $id("group-id").value = g.id;
      $id("group-name").value = g.name;
      $id("group-color").value = g.color;
      $id("group-save-btn").textContent = "Speichern";
      $id("group-cancel-btn").hidden = false;
      $id("group-name").focus();
      this.updatePresetSelection(g.color);
    },
    resetGroupForm() {
      $id("group-id").value = "";
      $id("group-name").value = "";
      $id("group-color").value = "#97a39d";
      $id("group-save-btn").textContent = "Hinzufügen";
      $id("group-cancel-btn").hidden = true;
      this.hideError("group-error");
      this.updatePresetSelection("#97a39d");
    },
    async saveGroupFromForm() {
      const id = $id("group-id").value;
      const name = $id("group-name").value.trim();
      const color = $id("group-color").value;
      if (!name) {
        this.showError("group-error", "Bitte einen Gruppennamen angeben.");
        return;
      }
      const saved = await this.trySave(
        () => (id ? Groups.update(id, name, color) : Groups.add(name, color)),
        "group-error"
      );
      if (!saved) return;
      this.toast(id ? "Gruppe aktualisiert ✓" : "Gruppe hinzugefügt ✓", "success");
      this.resetGroupForm();
      this.renderGroupList();
      this.renderFilterGroupOptions();
      this.renderEntryGroupOptions();
      this.renderList();
      this.refreshSelectedCard(); // Gruppen-Badge in der Card ggf. aktualisieren
    },
    confirmDeleteGroup(g) {
      const count = Groups.countEntries(g.id);
      const note =
        count > 0
          ? ` ${count} zugeordnete Einträge verlieren ihre Gruppe (werden nicht gelöscht).`
          : "";
      this.openConfirm("Gruppe löschen", `„${g.name}" löschen?${note}`, async () => {
        if (!(await this.trySave(() => Groups.remove(g.id)))) return;
        this.renderGroupList();
        this.renderFilterGroupOptions();
        this.renderEntryGroupOptions();
        this.renderList();
        this.refreshSelectedCard(); // Badge des ausgewählten Eintrags ggf. auf „Ohne Gruppe"
        this.toast("Gruppe gelöscht", "");
      });
    },

    /* ---------- Import ---------- */
    bindImport() {
      $id("import-file").addEventListener("change", (ev) => this.handleImportFile(ev));
      $id("btn-import-replace").addEventListener("click", () => this.doImport("replace"));
      $id("btn-import-merge").addEventListener("click", () => this.doImport("merge"));
      // Passwort-Dialog für verschlüsselte Importdateien
      $id("import-pw-form").addEventListener("submit", (ev) => {
        ev.preventDefault();
        this.submitImportPassword();
      });
    },
    handleImportFile(ev) {
      const file = ev.target.files[0];
      ev.target.value = ""; // erneutes Auswählen derselben Datei erlauben
      if (!file) return;
      // Plausibler Größenrahmen, um Hänger bei riesigen Dateien zu vermeiden
      if (file.size > 10 * 1024 * 1024) {
        this.toast("Datei zu groß (max. 10 MB).", "error", 5000);
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        let data;
        try {
          data = JSON.parse(reader.result);
        } catch (e) {
          this.toast("Import fehlgeschlagen: ungültige JSON-Datei.", "error", 5000);
          return;
        }
        // Verschlüsselte Datei? → Passwort abfragen
        if (ImportExport.isEncrypted(data)) {
          this.encryptedImportBlob = data;
          $id("import-pw-input").value = "";
          this.hideError("import-pw-error");
          this.openModal("import-pw-modal");
          setTimeout(() => $id("import-pw-input").focus(), 0);
          return;
        }
        // Klartext-Datei
        try {
          ImportExport.validate(data);
          this.showImportSummary(data);
        } catch (e) {
          this.toast("Import fehlgeschlagen: " + e.message, "error", 5000);
        }
      };
      reader.onerror = () => this.toast("Datei konnte nicht gelesen werden.", "error");
      reader.readAsText(file);
    },
    /** Entschlüsselt die ausgewählte Datei mit dem eingegebenen Passwort. */
    async submitImportPassword() {
      if (!this.encryptedImportBlob) return;
      const pw = $id("import-pw-input").value;
      try {
        const payload = await ImportExport.decryptImport(this.encryptedImportBlob, pw);
        ImportExport.validate(payload);
        this.encryptedImportBlob = null;
        this.closeModal("import-pw-modal");
        this.showImportSummary(payload);
      } catch (e) {
        this.showError("import-pw-error", "Falsches Passwort oder beschädigte Datei.");
      }
    },
    /** Zeigt die Replace/Merge-Auswahl mit Zusammenfassung. */
    showImportSummary(data) {
      this.pendingImport = data;
      $id("import-summary").textContent =
        `Gefunden: ${data.groups.length} Gruppen, ${data.entries.length} Einträge.`;
      this.hideError("import-error");
      this.openModal("import-modal");
    },
    async doImport(mode) {
      if (!this.pendingImport) return;
      try {
        if (mode === "replace") await ImportExport.replace(this.pendingImport);
        else await ImportExport.merge(this.pendingImport);
        this.pendingImport = null;
        this.closeModal("import-modal");
        this.renderAll();
        this.setUnsaved(false);
        this.toast(
          mode === "replace" ? "Daten ersetzt ✓" : "Daten ergänzt ✓",
          "success"
        );
      } catch (e) {
        this.showError("import-error", "Import fehlgeschlagen: " + e.message);
        this.setUnsaved(true);
      }
    },

    /* ---------- Bestätigungsdialog ---------- */
    bindConfirm() {
      $id("confirm-ok").addEventListener("click", async () => {
        const cb = this.confirmCallback;
        this.confirmCallback = null;
        this.confirmCancel = null; // Abbruch-Hook entschärfen, bevor geschlossen wird
        this.closeModal("confirm-modal");
        if (cb) await cb();
      });
    },
    /** opts: { okLabel, danger, onCancel } – OK-Beschriftung/-Stil + Abbruch-Hook. */
    openConfirm(title, message, callback, opts) {
      const o = opts || {};
      // Etwaigen wartenden Vorgänger auflösen, damit kein confirmAsync hängt
      if (this.confirmCancel) this.confirmCancel();
      $id("confirm-title").textContent = title;
      $id("confirm-message").textContent = message;
      const okBtn = $id("confirm-ok");
      okBtn.textContent = o.okLabel || "Löschen";
      okBtn.className = "btn " + (o.danger === false ? "btn-primary" : "btn-danger");
      this.confirmCallback = callback;
      this.confirmCancel = o.onCancel || null;
      this.openModal("confirm-modal");
    },
    /**
     * Promise-Variante von openConfirm — löst auch beim Abbrechen auf (false).
     * Nötig für Abläufe, die auf die Entscheidung warten (z. B. Datei-Konflikt).
     */
    confirmAsync(title, message, opts) {
      return new Promise((resolve) => {
        const o = Object.assign({}, opts, { onCancel: () => resolve(false) });
        this.openConfirm(title, message, () => resolve(true), o);
      });
    },

    /** Kurzes „Kopiert ✓"-Feedback am Button. */
    copyFeedback(btn, ok) {
      if (!ok) {
        this.toast("Kopieren nicht möglich (leer?).", "error");
        return;
      }
      const original = btn.innerHTML;
      // Icon-Buttons: nur „✓" (schmal), sonst „Kopiert ✓"
      btn.innerHTML = btn.classList.contains("icon-btn") ? "✓" : "Kopiert ✓";
      btn.classList.add("copied");
      setTimeout(() => {
        btn.innerHTML = original;
        btn.classList.remove("copied");
      }, 1200);
    },

    /* ---------- Modal-Grundfunktionen ---------- */
    /** Modale, die weder per ESC noch per Overlay-Klick schließen (Eingaben gehen sonst verloren). */
    CLOSE_ONLY_X: new Set(["entry-modal", "generator-modal"]),
    openModal(id) {
      $id(id).hidden = false;
    },
    closeModal(id) {
      $id(id).hidden = true;
      // Zugehörigen Schwebe-Status aufräumen (auch bei ESC/Overlay-Schließen)
      if (id === "confirm-modal") {
        const cancel = this.confirmCancel;
        this.confirmCallback = null;
        this.confirmCancel = null;
        if (cancel) cancel(); // wartende confirmAsync-Aufrufer auflösen
      }
      if (id === "import-modal") this.pendingImport = null;
      // Kein Klartext in versteckten Feldern/Listen zurücklassen (Passwörter,
      // Master-Passwort einer Importdatei, Gruppennamen …).
      if (id === "import-pw-modal") {
        this.encryptedImportBlob = null;
        $id("import-pw-input").value = "";
      }
      if (id === "restore-pw-modal") {
        App._restoreBlob = null;
        $id("restore-pw-input").value = "";
      }
      if (id === "entry-modal") $id("entry-form").reset();
      if (id === "generator-modal") $id("gen-result").value = "";
      this.resetPasswordToggles($id(id)); // Passwortfelder im Dialog wieder verbergen
      if (id === "groups-modal") $id("group-list").innerHTML = "";
      if (id === "print-modal") $id("print-group-list").innerHTML = "";
    },
    /** Schließt alle offenen Modale über closeModal() (inkl. Aufräumen). */
    closeAllModals() {
      document.querySelectorAll(".modal-overlay").forEach((m) => {
        if (!m.hidden) this.closeModal(m.id);
      });
    },
    bindGlobalClose() {
      // Schließen-Buttons (× und „Abbrechen") mit data-close
      document.querySelectorAll("[data-close]").forEach((btn) => {
        btn.addEventListener("click", () => this.closeModal(btn.getAttribute("data-close")));
      });
      // Klick auf Overlay-Hintergrund schließt das Modal (außer bei „nur ×"-Modalen)
      document.querySelectorAll(".modal-overlay").forEach((overlay) => {
        overlay.addEventListener("click", (ev) => {
          if (ev.target === overlay && !this.CLOSE_ONLY_X.has(overlay.id))
            this.closeModal(overlay.id);
        });
      });
      // ESC schließt das oberste sichtbare Modal (außer bei „nur ×"-Modalen)
      document.addEventListener("keydown", (ev) => {
        if (ev.key !== "Escape") return;
        const open = Array.from(document.querySelectorAll(".modal-overlay")).filter(
          (m) => !m.hidden
        );
        if (!open.length) return;
        const top = open[open.length - 1];
        if (this.CLOSE_ONLY_X.has(top.id)) return;
        this.closeModal(top.id);
      });
    },

    /* ---------- Hilfsfunktionen: Fehler & Toasts ---------- */
    showError(id, msg) {
      const el = $id(id);
      el.textContent = msg;
      el.hidden = false;
    },
    hideError(id) {
      $id(id).hidden = true;
    },
    /**
     * Führt eine speichernde Aktion aus und meldet Fehler sichtbar (Fail-loud).
     * Ohne diesen Schutz bliebe ein fehlgeschlagenes Store.persist() unbemerkt —
     * der Nutzer hielte ungespeicherte Daten für gesichert.
     * @param {Function} action asynchrone Aktion, die persist() auslöst
     * @param {string} [errorId] ID eines Fehler-Elements (im Modal); sonst Toast
     * @returns {Promise<boolean>} true = erfolgreich
     */
    async trySave(action, errorId) {
      try {
        await action();
        this.setUnsaved(false);
        return true;
      } catch (e) {
        const msg = "Speichern fehlgeschlagen: " + e.message;
        if (errorId) this.showError(errorId, msg);
        else this.toast(msg, "error", 5000);
        this.setUnsaved(true);
        return false;
      }
    },
    /** Dauerhafter Warnhinweis im Header, falls ein Speichern scheiterte. */
    setUnsaved(on) {
      $id("vault-unsaved").hidden = !on;
    },
    /** Zeigt den Header-Button „Tresor lösen", solange eine Tresor-Datei verknüpft ist. */
    updateVaultFile() {
      $id("vault-file").hidden = !FileVault.isLinked();
    },
    /** Info-Modal zur verknüpften Tresor-Datei (mit Button „Verknüpfung lösen"). */
    openUnlinkModal() {
      if (!FileVault.isLinked()) return;
      $id("unlink-file").textContent = FileVault.handle.name;
      let saved = "unbekannt";
      if (Store.savedAt) {
        const d = new Date(Store.savedAt);
        saved =
          d.toLocaleDateString("de-DE") +
          ", " +
          d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" }) +
          " Uhr";
      }
      $id("unlink-saved").textContent = saved;
      const n = Entries.all().length;
      const g = Groups.all().length;
      $id("unlink-content").textContent =
        `${n} ${n === 1 ? "Eintrag" : "Einträge"}, ${g} ${g === 1 ? "Gruppe" : "Gruppen"}`;
      this.openModal("unlink-modal");
    },
    toast(msg, type, duration) {
      const el = document.createElement("div");
      el.className = "toast" + (type ? " " + type : "");
      el.textContent = msg;
      $id("toast-container").appendChild(el);
      setTimeout(() => el.remove(), duration || 2200);
    },
  };

  /* ==============================================================
     Hilfsfunktion: HTML-Escaping (gegen Injection beim innerHTML)
     ============================================================== */
  function esc(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /** Prüft, ob ein String eine gültige Hex-Farbe ist (#rgb / #rrggbb / #rrggbbaa). */
  function isHexColor(value) {
    return typeof value === "string" && /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(value);
  }

  /**
   * Liefert eine gefahrlos in style-Attribute einsetzbare Farbe: gültige Hex-Farbe
   * oder Fallback. Gegen CSS-Injection aus Alt-/Fremddaten (esc() allein reicht nicht).
   */
  function safeColor(value, fallback) {
    return isHexColor(value) ? value : fallback || "#9ca3af";
  }

  /**
   * Lässt für klickbare Links nur unbedenkliche Schemata zu (http/https/mailto).
   * Verhindert ausführbare URLs wie javascript:/data: in importierten/eingegebenen
   * Werten. Gibt die getrimmte URL zurück oder "" bei unzulässigem Schema.
   */
  function safeUrl(value) {
    const u = String(value == null ? "" : value).trim();
    return /^(https?:|mailto:)/i.test(u) ? u : "";
  }

  /** Wandelt eine Hex-Farbe (#rgb / #rrggbb) in rgba() mit Alpha um. */
  function hexToRgba(hex, alpha) {
    let h = String(hex || "").replace("#", "");
    if (h.length === 3) h = h.split("").map((c) => c + c).join("");
    if (h.length !== 6) return `rgba(156,163,175,${alpha})`; // Fallback Grau
    const r = parseInt(h.slice(0, 2), 16);
    const g = parseInt(h.slice(2, 4), 16);
    const b = parseInt(h.slice(4, 6), 16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  /* ==============================================================
     APP — Bootstrap und Unlock-Flow
     ============================================================== */
  const App = {
    pendingRestoreData: null, // normalisierte Klartext-Daten, die nach Setup geladen werden
    _restoreBlob: null, // verschlüsselte Backup-Datei, die auf ihr Passwort wartet
    fileState: "none", // "linked" | "needs-permission" | "none"

    init() {
      // Web-Crypto-Verfügbarkeit prüfen
      if (!window.crypto || !crypto.subtle) {
        document.body.innerHTML =
          '<p style="padding:40px;font-family:sans-serif">' +
          "Dieser Browser unterstützt die Web Crypto API nicht. " +
          "Bitte öffne die App über <strong>file://</strong> oder <strong>http(s)</strong> " +
          "in einem modernen Browser.</p>";
        return;
      }
      this.bindLockScreen();
      // Fremde Änderungen an der Tresor-Datei (z. B. zweiter Tab) nicht still
      // überschreiben, sondern den Nutzer entscheiden lassen.
      Store.onFileConflict = () =>
        UI.confirmAsync(
          "Datei wurde geändert",
          "Die Tresor-Datei wurde zwischenzeitlich außerhalb dieses Fensters " +
            "geändert (z. B. in einem zweiten Tab). Beim Überschreiben gehen " +
            "jene Änderungen verloren.",
          { okLabel: "Überschreiben" }
        );
      // Verschwundene Datei würde Chrome über das gemerkte Handle still neu
      // anlegen — das soll der Nutzer bewusst entscheiden.
      Store.onFileMissing = () =>
        UI.confirmAsync(
          "Tresor-Datei nicht gefunden",
          "Die verknüpfte Tresor-Datei existiert nicht mehr — sie wurde gelöscht, " +
            "verschoben oder umbenannt. Soll sie am ursprünglichen Ort neu " +
            "angelegt werden?",
          { okLabel: "Neu anlegen", danger: false }
        );
      // Zuletzt verknüpfte Tresor-Datei anbinden, bevor der Lock-Screen entscheidet,
      // ob Setup oder Unlock gezeigt wird. Der Lock-Screen MUSS in jedem Fall
      // erscheinen – ohne showLock() bleiben beide Formulare ausgeblendet.
      FileVault.tryReconnect()
        .catch((e) => {
          console.error("Tresor-Datei konnte nicht angebunden werden.", e);
          FileVault.handle = null; // kein halb gesetztes Handle zurücklassen
          return "lost";
        })
        .then((state) => {
          this.fileState = state;
          this.showLock();
        });
    },

    /**
     * Zeigt Setup- oder Unlock-Formular je nach vorhandenem Tresor.
     * @param {boolean} [forceSetup] erzwingt das Setup (neue Tresor-Datei)
     */
    showLock(forceSetup) {
      // Etwaigen Wiederherstellungs-Status verwerfen (normaler Lock-Screen)
      this.pendingRestoreData = null;
      this._restoreBlob = null;
      $id("setup-restore-note").hidden = true;

      $id("lock-screen").hidden = false;
      $id("app").hidden = true;
      UI.resetPasswordToggles($id("lock-screen")); // kein Klartext vom letzten Mal
      this.renderLockFile();
      const hasVault = !forceSetup && (FileVault.isLinked() || Store.exists());
      $id("setup-form").hidden = hasVault;
      $id("unlock-form").hidden = !hasVault;
      // „Tresor zurücksetzen" (Sektion Notfall) nur, wenn es etwas zurückzusetzen gibt
      $id("reset-vault").hidden = !hasVault;
      if (hasVault) $id("unlock-password").focus();
      else $id("setup-password").focus();
    },

    /** Stellt den Zustand der Datei-Verknüpfung auf dem Lock-Screen dar. */
    renderLockFile() {
      const box = $id("lock-filevault");
      box.hidden = !FileVault.isSupported();
      if (box.hidden) return;
      const linked = FileVault.isLinked();
      const needsPerm = this.fileState === "needs-permission";
      const lost = !linked && this.fileState === "lost";
      $id("lock-file-status").textContent = lost
        ? `Die Verknüpfung mit „${FileVault.lostName || "der Tresor-Datei"}" ist nicht ` +
          "mehr gültig (z. B. nach einer Neuinstallation des Browsers). Die Datei selbst " +
          "ist unverändert – wähle sie über „Tresor-Datei öffnen\" erneut aus."
        : !linked
        ? "Wo liegt dein Tresor? Standardmäßig im Browser – alternativ in einer " +
          "Datei auf deinem Computer (z. B. für Sync oder eigene Sicherungen)."
        : needsPerm
        ? "Dein Tresor liegt in einer Datei. Der Browser braucht einmalig deine " +
          "Erlaubnis, um darauf zuzugreifen."
        : "Dein Tresor liegt in einer Datei auf deinem Computer.";
      $id("lock-file-status").classList.toggle("is-warn", lost);
      // Statuskacheln: aktiver Speicherort markiert (textContent → kein XSS)
      $id("lock-tile-browser").classList.toggle("is-active", !linked && !lost);
      $id("lock-tile-file").hidden = !linked;
      $id("lock-file-name").textContent = linked ? FileVault.handle.name : "";
      $id("btn-file-grant").hidden = !needsPerm;
      $id("btn-file-unlink").hidden = !linked;
      $id("btn-file-open").hidden = linked;
      $id("btn-file-new").hidden = linked;
    },

    /**
     * Verknüpft eine Tresor-Datei. isNew legt eine neue Datei an und erzwingt
     * anschließend das Setup-Formular (Master-Passwort des neuen Tresors).
     */
    async linkFile(isNew) {
      // Im Datei-Modus liegt der Tresor ausschließlich in der Datei. Ein bereits
      // im Browser gespeicherter Tresor muss deshalb weichen — sonst bliebe er
      // als veralteter Zweitstand liegen und tauchte beim Lösen wieder auf.
      if (Store.exists()) {
        const ok = await UI.confirmAsync(
          "In den Datei-Modus wechseln",
          "In diesem Browser ist bereits ein Tresor gespeichert. Er wird entfernt — " +
            "die Daten liegen danach ausschließlich in der gewählten Datei. Lege " +
            "vorher bei Bedarf ein Backup an (Export).",
          { okLabel: "Fortfahren" }
        );
        if (!ok) return;
      }
      try {
        const handle = isNew ? await FileVault.pickNew() : await FileVault.pickExisting();
        await FileVault.link(handle);
        Store.destroy(); // Browser-Tresor entfernen – die Datei ist ab jetzt die Quelle
        this.fileState = "linked";
        Store.savedAt = null; // Zeitstempel gehört zur bisherigen Quelle
        this.showLock(isNew);
        UI.toast("Tresor-Datei verknüpft ✓", "success");
      } catch (e) {
        // AbortError = Nutzer hat den Datei-Dialog abgebrochen
        if (e.name !== "AbortError")
          UI.toast("Verknüpfen fehlgeschlagen: " + e.message, "error", 5000);
      }
    },

    /** Nach Browser-Neustart den Zugriff erneut bestätigen (User-Geste nötig). */
    async grantFileAccess() {
      if (await FileVault.grantPermission()) {
        this.fileState = "linked";
        this.showLock();
      } else UI.toast("Zugriff auf die Datei wurde nicht erteilt.", "error", 5000);
    },

    /**
     * Verknüpfung lösen – die Datei selbst bleibt unangetastet.
     * Entsperrt: der Tresor wandert in den Browser (wird sofort dort gespeichert).
     * Gesperrt: es bleibt nichts zurück — ohne die Datei kein Tresor.
     */
    async unlinkFile() {
      const unlocked = !!Store.cryptoKey;
      await FileVault.unlink();
      this.fileState = "none";
      UI.updateVaultFile();
      if (unlocked) {
        // Ab jetzt im Browser speichern – Tresor sofort dort anlegen, damit kein
        // Zustand ohne Speicherort entsteht.
        const ok = await UI.trySave(() => Store.persist());
        if (ok) UI.toast("Verknüpfung gelöst – gespeichert wird jetzt im Browser.", "");
      } else {
        Store.destroy(); // keine Browser-Kopie zurücklassen
        this.showLock();
        UI.toast("Verknüpfung gelöst – die Datei bleibt erhalten.", "");
      }
    },

    bindLockScreen() {
      // Erststart: Tresor erstellen
      $id("setup-form").addEventListener("submit", async (ev) => {
        ev.preventDefault();
        UI.hideError("setup-error");
        const pw = $id("setup-password").value;
        const repeat = $id("setup-password-repeat").value;
        if (pw.length < 10) {
          UI.showError("setup-error", "Master-Passwort muss mindestens 10 Zeichen lang sein. Empfohlen: eine lange Passphrase.");
          return;
        }
        if (pw !== repeat) {
          UI.showError("setup-error", "Die Passwörter stimmen nicht überein.");
          return;
        }
        try {
          // Falls eine Klartext-Backup-Datei geladen wurde, deren Daten übernehmen
          await Store.create(pw, this.pendingRestoreData);
          const restored = !!this.pendingRestoreData;
          this.pendingRestoreData = null;
          $id("setup-restore-note").hidden = true;
          $id("setup-password").value = "";
          $id("setup-password-repeat").value = "";
          this.enterApp();
          if (restored) UI.toast("Backup wiederhergestellt ✓", "success");
        } catch (e) {
          // Schlüssel/Daten des gescheiterten Versuchs nicht im Speicher belassen
          Store.lock();
          UI.showError("setup-error", "Tresor konnte nicht erstellt werden: " + e.message);
        }
      });

      // Folgestart: entsperren
      $id("unlock-form").addEventListener("submit", async (ev) => {
        ev.preventDefault();
        UI.hideError("unlock-error");
        const pw = $id("unlock-password").value;
        try {
          if (FileVault.isLinked()) await Store.unlockFromFile(pw);
          else await Store.unlock(pw);
          $id("unlock-password").value = "";
          this.enterApp();
        } catch (e) {
          // Bei gescheitertem Speichern (Migration) ist der Schlüssel schon gesetzt –
          // auf dem Lock-Screen darf er nicht im Speicher bleiben.
          Store.lock();
          UI.showError(
            "unlock-error",
            e.fileError ? e.message : "Falsches Master-Passwort oder beschädigte Daten."
          );
        }
      });

      // Tresor zurücksetzen
      $id("reset-vault").addEventListener("click", () => {
        UI.openConfirm(
          "Tresor zurücksetzen",
          "Alle im Browser gespeicherten Daten werden unwiderruflich gelöscht und " +
            "eine etwaige Datei-Verknüpfung wird gelöst (die Datei selbst bleibt " +
            "erhalten). Fortfahren?",
          async () => {
            Store.destroy();
            if (FileVault.isLinked()) await FileVault.unlink();
            this.fileState = "none";
            UI.toast("Tresor wurde zurückgesetzt.", "");
            this.showLock();
          }
        );
      });

      // Tresor-Datei verknüpfen (nur Chromium-Browser)
      if (FileVault.isSupported()) {
        $id("btn-file-open").addEventListener("click", () => this.linkFile(false));
        $id("btn-file-new").addEventListener("click", () => this.linkFile(true));
        $id("btn-file-grant").addEventListener("click", () => this.grantFileAccess());
        $id("btn-file-unlink").addEventListener("click", () =>
          UI.openConfirm(
            "Verknüpfung lösen",
            "Danach ist in diesem Browser kein Tresor mehr vorhanden. Die Datei " +
              "selbst bleibt erhalten und lässt sich jederzeit wieder öffnen.",
            () => this.unlinkFile(),
            { okLabel: "Verknüpfung lösen" }
          )
        );
      }
      // Header: „Tresor lösen" → Info-Modal, dort „Verknüpfung lösen"
      $id("vault-file").addEventListener("click", () => UI.openUnlinkModal());
      $id("btn-unlink-confirm").addEventListener("click", () => {
        UI.closeModal("unlink-modal");
        this.unlinkFile();
      });

      // Passwort-Generator auch auf dem Lock-Screen; bei der Ersteinrichtung mit
      // „Als Master-Passwort übernehmen"
      $id("lock-gen-btn").addEventListener("click", () =>
        UI.openGenerator($id("setup-form").hidden ? null : "master")
      );

      // Anleitung öffnen (file://-tauglich, ohne Inline-Handler)
      $id("lock-help-link").addEventListener("click", () =>
        window.open("anleitung.html", "_blank", "noopener")
      );

      // Wiederherstellung aus Backup-Datei
      $id("restore-file-btn").addEventListener("click", () => $id("restore-file").click());
      $id("restore-file").addEventListener("change", (ev) => this.handleRestoreFile(ev));
      $id("restore-pw-form").addEventListener("submit", (ev) => {
        ev.preventDefault();
        this.submitRestorePassword();
      });
    },

    /** Liest eine Backup-Datei und startet je nach Typ den passenden Restore-Weg. */
    handleRestoreFile(ev) {
      const file = ev.target.files[0];
      ev.target.value = "";
      if (!file) return;
      if (file.size > 10 * 1024 * 1024) {
        UI.toast("Datei zu groß (max. 10 MB).", "error", 5000);
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        let data;
        try {
          data = JSON.parse(reader.result);
        } catch (e) {
          UI.toast("Wiederherstellung fehlgeschlagen: ungültige JSON-Datei.", "error", 5000);
          return;
        }
        if (ImportExport.isEncrypted(data)) {
          // Verschlüsseltes Backup → Passwort der Datei abfragen
          this.confirmOverwriteIfNeeded(() => {
            this._restoreBlob = data;
            $id("restore-pw-input").value = "";
            UI.hideError("restore-pw-error");
            UI.openModal("restore-pw-modal");
            setTimeout(() => $id("restore-pw-input").focus(), 0);
          });
        } else {
          // Klartext-Backup → Struktur prüfen, dann neues Master-Passwort festlegen
          try {
            ImportExport.validate(data);
          } catch (e) {
            UI.toast("Wiederherstellung fehlgeschlagen: " + e.message, "error", 5000);
            return;
          }
          this.confirmOverwriteIfNeeded(() =>
            this.showSetupForRestore(ImportExport.normalize(data))
          );
        }
      };
      reader.onerror = () => UI.toast("Datei konnte nicht gelesen werden.", "error");
      reader.readAsText(file);
    },

    /** Falls bereits ein Tresor existiert, vor dem Überschreiben bestätigen. */
    confirmOverwriteIfNeeded(proceed) {
      // Ohne erteilten Dateizugriff könnte der neue Tresor nicht gespeichert werden –
      // erst den Zugriff bestätigen lassen, statt später mit einem Fehler zu scheitern.
      if (this.fileState === "needs-permission") {
        UI.toast(
          "Bitte zuerst „Zugriff auf die Datei erlauben\" wählen oder die Verknüpfung lösen.",
          "error",
          6000
        );
        return;
      }
      const linked = FileVault.isLinked();
      if (!linked && !Store.exists()) {
        proceed();
        return;
      }
      UI.openConfirm(
        "Vorhandenen Tresor ersetzen",
        linked
          ? `Die verknüpfte Tresor-Datei „${FileVault.handle.name}" wird beim ` +
            "Wiederherstellen vollständig durch das Backup überschrieben. Fortfahren?"
          : "Es existiert bereits ein Tresor in diesem Browser. Beim Wiederherstellen wird " +
            "er vollständig durch das Backup ersetzt. Fortfahren?",
        () => proceed(),
        { okLabel: "Ersetzen" }
      );
    },

    /** Zeigt das Setup-Formular mit Hinweis, um Klartext-Backup-Daten zu übernehmen. */
    showSetupForRestore(normalizedData) {
      this.pendingRestoreData = normalizedData;
      $id("setup-form").hidden = false;
      $id("unlock-form").hidden = true;
      const note = $id("setup-restore-note");
      note.textContent =
        `Backup geladen: ${normalizedData.groups.length} Gruppen, ` +
        `${normalizedData.entries.length} Einträge. Lege ein neues Master-Passwort fest, ` +
        `um sie zu übernehmen.`;
      note.hidden = false;
      UI.hideError("setup-error");
      $id("setup-password").value = "";
      $id("setup-password-repeat").value = "";
      $id("setup-password").focus();
    },

    /** Entschlüsselt das Backup und legt damit den neuen Tresor an. */
    async submitRestorePassword() {
      if (!this._restoreBlob) return;
      const pw = $id("restore-pw-input").value;
      UI.hideError("restore-pw-error");
      // Schritt 1: Entschlüsseln + Prüfen – nur hier bedeutet ein Fehler
      // „falsches Passwort oder beschädigte Datei".
      let data;
      try {
        const payload = await ImportExport.decryptImport(this._restoreBlob, pw);
        ImportExport.validate(payload);
        data = ImportExport.normalize(payload);
      } catch (e) {
        UI.showError("restore-pw-error", "Falsches Passwort oder beschädigte Datei.");
        return;
      }
      // Schritt 2: Tresor anlegen + speichern – Fehler hier liegen am Speicherziel
      // (z. B. Tresor-Datei nicht erreichbar), nicht am Passwort.
      try {
        await Store.create(pw, data);
      } catch (e) {
        Store.lock(); // Schlüssel/Daten des gescheiterten Versuchs nicht im Speicher belassen
        UI.showError(
          "restore-pw-error",
          "Das Backup ist in Ordnung, der neue Tresor konnte aber nicht gespeichert werden: " +
            e.message
        );
        return;
      }
      this._restoreBlob = null;
      $id("restore-pw-input").value = "";
      UI.closeModal("restore-pw-modal");
      this.enterApp();
      UI.toast("Backup wiederhergestellt ✓", "success");
    },

    /** Wechselt nach erfolgreichem Unlock in die Hauptansicht. */
    enterApp() {
      // Hinweis auf eine verlorene Verknüpfung hat sich mit dem neuen Tresor erledigt
      if (this.fileState === "lost") this.fileState = "none";
      $id("lock-screen").hidden = true;
      $id("app").hidden = false;
      UI.resetPasswordToggles($id("lock-screen")); // Felder sind geleert – wieder verbergen
      UI.updateVaultFile();
      UI.setUnsaved(false);
      // Alle Gruppen beim Start zugeklappt anzeigen
      UI.collapsedGroups = new Set([
        ...Groups.all().map((g) => g.id),
        UI.NO_GROUP,
      ]);
      UI.renderAll();
      IdleLock.start(); // Inaktivitäts-Überwachung aktivieren
    },

    /** Sperrt den Tresor und kehrt zum Lock-Screen zurück. */
    lock(reason) {
      IdleLock.stop();
      // Offene Modale schließen: sie liegen über dem Lock-Screen (z-index 150 > 100)
      // und zeigten sonst z. B. das Eintragsformular samt Passwort weiter an.
      UI.closeAllModals();
      Clipboard.clearNow(); // ggf. kopiertes Geheimnis aus der Zwischenablage entfernen
      Store.lock();
      Filters.reset();
      // Info-Card leeren (setzt zugleich selectedId zurück): sonst bliebe der
      // Klartext des zuletzt gewählten Eintrags im DOM stehen und wäre nach dem
      // Anlegen/Entsperren eines anderen Tresors wieder sichtbar.
      UI.renderInfoCard(null);
      $id("entry-list").innerHTML = "";
      $id("search-input").value = "";
      $id("search-clear").hidden = true;
      $id("unlock-password").value = "";
      this.showLock();
      UI.toast(reason || "Tresor gesperrt.", "");
    },
  };

  /* ==============================================================
     Start
     ============================================================== */
  document.addEventListener("DOMContentLoaded", () => {
    Theme.init();
    UI.init();
    App.init();
  });
})();
