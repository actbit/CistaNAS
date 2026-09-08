// CistaNAS E2EE — Web Crypto API によるクライアント側暗号化モジュール
// Blazor から JSInterop 経由で呼び出される
// 鍵は JS 側の Map にキャッシュし、文字列ハンドルで参照する

const FILE_SALT_SIZE = 16;
const GCM_NONCE_SIZE = 12;
const GCM_TAG_SIZE = 16;

// 鍵ハンドルマネージャー
const _keys = new Map();
let _nextId = 1;

function storeKey(cryptoKey) {
    const id = "key_" + (_nextId++);
    _keys.set(id, cryptoKey);
    return id;
}

function getKey(handle) {
    const k = _keys.get(handle);
    if (!k) throw new Error("Invalid key handle: " + handle);
    return k;
}

function removeKey(handle) {
    _keys.delete(handle);
}

// ---- KDF ----

// KDF パラメータを正規化する。
// - 数値が渡された場合はレガシー PBKDF2 単段（既存データ互換）
// - オブジェクト { algorithm, iterations, memoryKiB, timeCost, parallelism } を受け取る。
//   algorithm === "argon2id" は合成 KDF:
//     KEK = PBKDF2-SHA256( Argon2id(password, salt, t, m, p), salt, iterations, 32 )
//   algorithm === "argon2id-raw" は Argon2id 単独（PBKDF2 後段なし）:
//     KEK = Argon2id(password, salt, t, m, p)
//   （.NET 側 KeyDerivation.DeriveKek / hash-wasm と同一規約。RFC 9106 ベクトルで相互運性検証済み）
function normalizeKdf(kdf) {
    if (typeof kdf === "number") {
        return { algorithm: "pbkdf2-sha256", iterations: kdf, memoryKiB: 0, timeCost: 0, parallelism: 0 };
    }
    const spec = kdf || {};
    return {
        algorithm: spec.algorithm || "pbkdf2-sha256",
        iterations: spec.iterations || 0,
        memoryKiB: spec.memoryKiB || 0,
        timeCost: spec.timeCost || 0,
        parallelism: spec.parallelism || 0,
    };
}

async function pbkdf2Bits(passwordBytes, salt, iterations) {
    if (!iterations || iterations < 1) throw new Error("PBKDF2 反復数が不正です。");
    const keyMaterial = await crypto.subtle.importKey(
        "raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, keyMaterial, 256));
}

// Argon2id (RFC 9106)。hash-wasm (wwwroot/js/argon2.umd.min.js, index.html で読み込み) を使用。
// メモリ困難性により GPU/ASIC での総当たり攻撃を困難にする。
async function argon2idBits(passwordBytes, salt, timeCost, memoryKiB, parallelism) {
    const hw = globalThis.hashwasm;
    if (!hw || typeof hw.argon2id !== "function") {
        throw new Error("hash-wasm (argon2) がロードされていません。");
    }
    return new Uint8Array(await hw.argon2id({
        password: passwordBytes,
        salt: salt,
        iterations: timeCost,
        parallelism: parallelism,
        memorySize: memoryKiB,
        hashLength: 32,
        outputType: "binary"
    }));
}

// KEK の raw ビット列（32 バイト）を導出する。combinedSalt は結合済みを想定。
async function deriveKekBits(password, combinedSalt, spec) {
    const enc = new TextEncoder();
    const passwordBytes = enc.encode(password);
    if (spec.algorithm === "argon2id") {
        const argonOut = await argon2idBits(passwordBytes, combinedSalt, spec.timeCost, spec.memoryKiB, spec.parallelism);
        try {
            // 後段 PBKDF2: Argon2id 実装が将来破られた場合の CPU 困難性バックストップ
            return await pbkdf2Bits(argonOut, combinedSalt, spec.iterations);
        } finally {
            argonOut.fill(0);
        }
    }
    if (spec.algorithm === "argon2id-raw") {
        // Argon2id 単独: RFC 9106 の出力をそのまま鍵として使う（後段変換なし）
        return argon2idBits(passwordBytes, combinedSalt, spec.timeCost, spec.memoryKiB, spec.parallelism);
    }
    return pbkdf2Bits(passwordBytes, combinedSalt, spec.iterations);
}

// Cross-platform compatibility: SHA256(username) || salt
// (matching KeyDerivation.CombineUserSalt / e2ee deriveKek)
async function combineUserSalt(username, salt) {
    if (!username) return salt;
    const userHash = new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(username)));
    return concatBufs(userHash, salt);
}

// ---- 鍵管理 ----

// kdf: { algorithm, iterations, memoryKiB, timeCost, parallelism }（数値はレガシー PBKDF2）
export async function deriveKek(password, saltBase64, kdf, username) {
    const spec = normalizeKdf(kdf);
    const salt = uint8FromBase64(saltBase64);
    const combinedSalt = await combineUserSalt(username, salt);

    const kekBits = await deriveKekBits(password, combinedSalt, spec);
    const kek = await crypto.subtle.importKey(
        "raw", kekBits, { name: "AES-GCM", length: 256 },
        false,
        ["wrapKey", "unwrapKey", "encrypt", "decrypt"]);
    kekBits.fill(0);

    return storeKey(kek);
}

export async function generateMasterKey() {
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    return storeKey(key);
}

export async function wrapMasterKey(masterKeyHandle, kekHandle) {
    const masterKey = getKey(masterKeyHandle);
    const kek = getKey(kekHandle);
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_SIZE));

    // exportKey("raw") で 32 バイトの鍵データを取り出し、AES-GCM で暗号化。
    // 出力フォーマット: ciphertext(32) || tag(16) — Web Crypto encrypt の標準形式。
    const rawKey = await crypto.subtle.exportKey("raw", masterKey);
    const wrapped = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 }, kek, rawKey);
    const buf = new Uint8Array(wrapped);
    return {
        nonce: uint8ToBase64(nonce),
        ciphertext: uint8ToBase64(buf.slice(0, 32)),
        tag: uint8ToBase64(buf.slice(32))
    };
}

export async function unwrapMasterKey(wrappedNonce, wrappedCt, wrappedTag, kekHandle) {
    const kek = getKey(kekHandle);
    const nonce = uint8FromBase64(wrappedNonce);
    const ct = uint8FromBase64(wrappedCt);
    const tag = uint8FromBase64(wrappedTag);

    // ciphertext || tag を復元して AES-GCM で復号 → importKey で CryptoKey に戻す。
    const raw = concatBufs(ct, tag);
    const rawKey = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 }, kek, raw);

    const masterKey = await crypto.subtle.importKey(
        "raw", rawKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

    return storeKey(masterKey);
}

export function clearKey(handle) {
    removeKey(handle);
}

export function clearAllKeys() {
    _keys.clear();
}

// ---- ファイル暗号化（チャンク単位） ----

async function deriveFileKey(masterKey, fileSalt) {
    const rawKey = await crypto.subtle.exportKey("raw", masterKey);
    const keyMaterial = await crypto.subtle.importKey("raw", rawKey, "HKDF", false, ["deriveKey"]);
    // extractable=true: encryptChunk/decryptChunk が nonce 導出のために fileKey の raw を exportKey する。
    // (CistaNAS.Web の E2eeCrypto.DeriveFileKey は byte[] を直接使うが、JS 側は CryptoKey から export する必要がある)
    return await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: fileSalt, info: new TextEncoder().encode("cista-file-key") },
        keyMaterial,
        { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

async function deriveChunkNonce(fileKeyRaw, chunkIndex, fileSalt, revision) {
    const chunkIndexBuf = new ArrayBuffer(4);
    new DataView(chunkIndexBuf).setUint32(0, chunkIndex, true);
    // Cross-platform compatibility: HMAC-SHA256(fileKey, fileSalt || chunkIndex [|| revision])
    // (matching E2eeCrypto.DeriveChunkNonce)
    // revision == 0 では入力に revision を含めない（既存ファイルと後方互換）。
    // revision > 0 では le32 revision を追加し、同じ chunkIndex の安全な再暗号化を可能にする。
    const bufs = [fileSalt, new Uint8Array(chunkIndexBuf)];
    if (revision > 0) {
        const revBuf = new ArrayBuffer(4);
        new DataView(revBuf).setUint32(0, revision, true);
        bufs.push(new Uint8Array(revBuf));
    }
    const data = concatBufs(...bufs);
    const key = await crypto.subtle.importKey("raw", fileKeyRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = await crypto.subtle.sign("HMAC", key, data);
    return new Uint8Array(mac).slice(0, GCM_NONCE_SIZE);
}

export async function encryptChunk(plainBase64, masterKeyHandle, chunkIndex, fileSaltBase64, isFirstChunk, revision = 0) {
    const masterKey = getKey(masterKeyHandle);
    const plainBytes = uint8FromBase64(plainBase64);
    const fileSalt = uint8FromBase64(fileSaltBase64);
    const fileKey = await deriveFileKey(masterKey, fileSalt);
    const fileKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
    const nonce = await deriveChunkNonce(fileKeyRaw, chunkIndex, fileSalt, revision);

    const aad = new ArrayBuffer(4);
    new DataView(aad).setUint32(0, chunkIndex, true);

    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        fileKey, plainBytes);

    const ctBuf = new Uint8Array(ct);
    const result = isFirstChunk ? concatBufs(fileSalt, ctBuf) : ctBuf;
    return uint8ToBase64(result);
}

export async function decryptChunk(encBase64, masterKeyHandle, chunkIndex, fileSaltBase64, revision = 0) {
    const masterKey = getKey(masterKeyHandle);
    let encBytes = uint8FromBase64(encBase64);
    const fileSalt = uint8FromBase64(fileSaltBase64);
    const fileKey = await deriveFileKey(masterKey, fileSalt);
    const fileKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
    const nonce = await deriveChunkNonce(fileKeyRaw, chunkIndex, fileSalt, revision);

    const aad = new ArrayBuffer(4);
    new DataView(aad).setUint32(0, chunkIndex, true);

    // チャンク 0 は salt(16) + ciphertext + tag(16) の形式で保存されている。
    // salt は fileSaltBase64 として別途渡されているため、ここでは ciphertext + tag のみを復号対象とする。
    let ciphertext = encBytes;
    if (chunkIndex === 0 && encBytes.length > FILE_SALT_SIZE + GCM_TAG_SIZE) {
        ciphertext = encBytes.slice(FILE_SALT_SIZE);
    }

    const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        fileKey, ciphertext);

    return uint8ToBase64(new Uint8Array(plain));
}

// ---- ファイル名暗号化 ----

export async function encryptFilename(plainName, masterKeyHandle) {
    const masterKey = getKey(masterKeyHandle);
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_SIZE));
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        masterKey, enc.encode(plainName));
    const ctBuf = new Uint8Array(ct);
    return uint8ToBase64(concatBufs(nonce, ctBuf));
}

export async function decryptFilename(encBase64, masterKeyHandle) {
    const masterKey = getKey(masterKeyHandle);
    const raw = uint8FromBase64(encBase64);
    const nonce = raw.slice(0, GCM_NONCE_SIZE);
    const ct = raw.slice(GCM_NONCE_SIZE);
    const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        masterKey, ct);
    return new TextDecoder().decode(plain);
}

// ---- ヘルパー ----

export function generateFileSalt() {
    return uint8ToBase64(crypto.getRandomValues(new Uint8Array(FILE_SALT_SIZE)));
}

function uint8ToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function uint8FromBase64(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function concatBufs(...bufs) {
    const total = bufs.reduce((sum, b) => sum + b.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const b of bufs) { result.set(b, offset); offset += b.length; }
    return result;
}

// ---- ECDH key pair management ----

export async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    return {
        publicKeyHandle: storeKey(keyPair.publicKey),
        privateKeyHandle: storeKey(keyPair.privateKey)
    };
}

export async function exportPublicKey(handle) {
    const key = getKey(handle);
    const raw = await crypto.subtle.exportKey("raw", key);
    return uint8ToBase64(new Uint8Array(raw));
}

// kdf: { algorithm, iterations, memoryKiB, timeCost, parallelism }（数値はレガシー PBKDF2）。
// ソルトは username を含まない raw salt（C# 側 encryptPrivateKey 経路と同一規約）。
export async function encryptPrivateKey(privKeyHandle, password, saltBase64, kdf) {
    const spec = normalizeKdf(kdf);
    const salt = uint8FromBase64(saltBase64);
    const kekBits = await deriveKekBits(password, salt, spec);
    const kek = await crypto.subtle.importKey(
        "raw", kekBits, { name: "AES-GCM", length: 256 }, false, ["wrapKey"]);
    kekBits.fill(0);
    const privateKey = getKey(privKeyHandle);
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_SIZE));
    const wrapped = await crypto.subtle.wrapKey("jwk", privateKey, kek,
        { name: "AES-GCM", iv: nonce });
    return {
        nonce: uint8ToBase64(nonce),
        wrapped: uint8ToBase64(new Uint8Array(wrapped))
    };
}

export async function decryptPrivateKey(wrappedBase64, nonceBase64, password, saltBase64, kdf) {
    const spec = normalizeKdf(kdf);
    const salt = uint8FromBase64(saltBase64);
    const kekBits = await deriveKekBits(password, salt, spec);
    const kek = await crypto.subtle.importKey(
        "raw", kekBits, { name: "AES-GCM", length: 256 }, false, ["unwrapKey"]);
    kekBits.fill(0);
    const nonce = uint8FromBase64(nonceBase64);
    const wrapped = uint8FromBase64(wrappedBase64);
    const privateKey = await crypto.subtle.unwrapKey("jwk", wrapped, kek,
        { name: "AES-GCM", iv: nonce },
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    return storeKey(privateKey);
}

// ---- ECIES wrap/unwrap (ECDH + HKDF + AES-256-GCM) ----

export async function ecdhWrap(masterKeyHandle, recipientPublicKeyBase64) {
    // 1. Ephemeral ECDH key pair
    const ephemeral = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);

    // 2. Import recipient public key
    const recipientPubRaw = uint8FromBase64(recipientPublicKeyBase64);
    const recipientPub = await crypto.subtle.importKey(
        "raw", recipientPubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);

    // 3. ECDH agree -> 256-bit shared secret
    const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: recipientPub }, ephemeral.privateKey, 256);

    // 4. HKDF-SHA256 -> wrapping key
    const wrappingKeyMaterial = await crypto.subtle.importKey(
        "raw", sharedBits, "HKDF", false, ["deriveKey"]);
    const wrappingKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
          info: new TextEncoder().encode("CistaNAS-ECIES") },
        wrappingKeyMaterial, { name: "AES-GCM", length: 256 }, false, ["wrapKey"]);

    // 5. Wrap master key
    const masterKey = getKey(masterKeyHandle);
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_SIZE));
    const wrapped = await crypto.subtle.wrapKey("raw", masterKey, wrappingKey,
        { name: "AES-GCM", iv: nonce });
    const wrappedBuf = new Uint8Array(wrapped); // ciphertext(32) + tag(16)

    // 6. Export ephemeral public key
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));

    return {
        ephemeralPublicKey: uint8ToBase64(ephPubRaw),
        nonce: uint8ToBase64(nonce),
        ciphertext: uint8ToBase64(wrappedBuf.slice(0, 32)),
        tag: uint8ToBase64(wrappedBuf.slice(32))
    };
}

export async function ecdhUnwrap(nonceBase64, ciphertextBase64, tagBase64,
                                  ephemeralPublicKeyBase64, privateKeyHandle) {
    // 1. Import ephemeral public key
    const ephPubRaw = uint8FromBase64(ephemeralPublicKeyBase64);
    const ephPub = await crypto.subtle.importKey(
        "raw", ephPubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);

    // 2. ECDH agree -> same shared secret
    const privateKey = getKey(privateKeyHandle);
    const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: ephPub }, privateKey, 256);

    // 3. HKDF -> same wrapping key
    const wrappingKeyMaterial = await crypto.subtle.importKey(
        "raw", sharedBits, "HKDF", false, ["deriveKey"]);
    const wrappingKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
          info: new TextEncoder().encode("CistaNAS-ECIES") },
        wrappingKeyMaterial, { name: "AES-GCM", length: 256 }, false, ["unwrapKey"]);

    // 4. Unwrap master key
    const nonce = uint8FromBase64(nonceBase64);
    const ct = uint8FromBase64(ciphertextBase64);
    const tag = uint8FromBase64(tagBase64);
    const raw = concatBufs(ct, tag);

    const masterKey = await crypto.subtle.unwrapKey("raw", raw, wrappingKey,
        { name: "AES-GCM", iv: nonce },
        { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

    return storeKey(masterKey);
}

// ---- Invitation key exchange helpers ----

export async function deriveInvitationKey(secretBase64) {
    const secret = uint8FromBase64(secretBase64);
    const keyMaterial = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
          info: new TextEncoder().encode("CistaNAS-Invite") },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
}

export async function encryptForInvitation(dataBase64, invitationKeyHandle) {
    const data = uint8FromBase64(dataBase64);
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_SIZE));
    const key = getKey(invitationKeyHandle);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data);
    return {
        nonce: uint8ToBase64(nonce),
        ciphertext: uint8ToBase64(new Uint8Array(ct))
    };
}

export async function decryptFromInvitation(ciphertextBase64, nonceBase64, invitationKeyHandle) {
    const nonce = uint8FromBase64(nonceBase64);
    const ct = uint8FromBase64(ciphertextBase64);
    const key = getKey(invitationKeyHandle);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
    return uint8ToBase64(new Uint8Array(plain));
}

// ---- グローバル公開（非モジュールスクリプトからの呼び出し用） ----

window.cistaE2ee = { decryptChunk, generateFileSalt };
