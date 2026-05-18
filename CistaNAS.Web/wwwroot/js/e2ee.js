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

// ---- 鍵管理 ----

export async function deriveKek(password, saltBase64, iterations) {
    const salt = uint8FromBase64(saltBase64);
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]);

    const kek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["wrapKey", "unwrapKey", "encrypt", "decrypt"]);

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
    const wrapped = await crypto.subtle.wrapKey("raw", masterKey, kek,
        { name: "AES-GCM", iv: nonce });
    const buf = new Uint8Array(wrapped);
    // Web Crypto wrapped = nonce(12) || ciphertext(32) || tag(16)
    return {
        nonce: uint8ToBase64(nonce),
        ciphertext: uint8ToBase64(buf.slice(GCM_NONCE_SIZE, GCM_NONCE_SIZE + 32)),
        tag: uint8ToBase64(buf.slice(GCM_NONCE_SIZE + 32))
    };
}

export async function unwrapMasterKey(wrappedNonce, wrappedCt, wrappedTag, kekHandle) {
    const kek = getKey(kekHandle);
    const nonce = uint8FromBase64(wrappedNonce);
    const ct = uint8FromBase64(wrappedCt);
    const tag = uint8FromBase64(wrappedTag);
    const raw = concatBufs(nonce, ct, tag);

    const masterKey = await crypto.subtle.unwrapKey("raw", raw, kek,
        { name: "AES-GCM", iv: nonce },
        { name: "AES-GCM", length: 256 },
        true, ["encrypt", "decrypt"]);

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
    return await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: fileSalt, info: new TextEncoder().encode("cista-file-key") },
        keyMaterial,
        { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function deriveChunkNonce(fileKeyRaw, chunkIndex) {
    const chunkIndexBuf = new ArrayBuffer(4);
    new DataView(chunkIndexBuf).setUint32(0, chunkIndex, true);
    const hash = await crypto.subtle.digest("SHA-256", concatBufs(fileKeyRaw, new Uint8Array(chunkIndexBuf)));
    return new Uint8Array(hash).slice(0, GCM_NONCE_SIZE);
}

export async function encryptChunk(plainBase64, masterKeyHandle, chunkIndex, fileSaltBase64, isFirstChunk) {
    const masterKey = getKey(masterKeyHandle);
    const plainBytes = uint8FromBase64(plainBase64);
    const fileSalt = uint8FromBase64(fileSaltBase64);
    const fileKey = await deriveFileKey(masterKey, fileSalt);
    const fileKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
    const nonce = await deriveChunkNonce(fileKeyRaw, chunkIndex);

    const aad = new ArrayBuffer(4);
    new DataView(aad).setUint32(0, chunkIndex, true);

    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        fileKey, plainBytes);

    const ctBuf = new Uint8Array(ct);
    const result = isFirstChunk ? concatBufs(fileSalt, ctBuf) : ctBuf;
    return uint8ToBase64(result);
}

export async function decryptChunk(encBase64, masterKeyHandle, chunkIndex, fileSaltBase64) {
    const masterKey = getKey(masterKeyHandle);
    const encBytes = uint8FromBase64(encBase64);
    const fileSalt = uint8FromBase64(fileSaltBase64);
    const fileKey = await deriveFileKey(masterKey, fileSalt);
    const fileKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
    const nonce = await deriveChunkNonce(fileKeyRaw, chunkIndex);

    const aad = new ArrayBuffer(4);
    new DataView(aad).setUint32(0, chunkIndex, true);

    const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        fileKey, encBytes);

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
