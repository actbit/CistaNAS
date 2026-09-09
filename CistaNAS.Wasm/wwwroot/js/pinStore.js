// 公開鍵 pin（TOFU trust anchor）の IndexedDB ストレージ。
// origin ローカルにのみ保存され、サーバーには送信されない。
// レコード: { username, fingerprintSha256, createdAt, updatedAt }

const DB_NAME = "cista-e2ee-pins";
const DB_VERSION = 1;
const STORE_NAME = "pins";

function openDb() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: "username" });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function getPin(username) {
    const db = await openDb();
    try {
        return await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readonly");
            const req = tx.objectStore(STORE_NAME).get(username);
            req.onsuccess = () => resolve(req.result || null);
            req.onerror = () => reject(req.error);
        });
    } finally {
        db.close();
    }
}

export async function putPin(username, fingerprintSha256) {
    const db = await openDb();
    try {
        const existing = await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readonly");
            const req = tx.objectStore(STORE_NAME).get(username);
            req.onsuccess = () => resolve(req.result || null);
            req.onerror = () => reject(req.error);
        });
        const now = new Date().toISOString();
        const record = {
            username,
            fingerprintSha256,
            createdAt: existing?.createdAt || now,
            updatedAt: now,
        };
        await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readwrite");
            tx.objectStore(STORE_NAME).put(record);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
        return record;
    } finally {
        db.close();
    }
}

export async function deletePin(username) {
    const db = await openDb();
    try {
        await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readwrite");
            tx.objectStore(STORE_NAME).delete(username);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    } finally {
        db.close();
    }
}

export async function listPins() {
    const db = await openDb();
    try {
        return await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readonly");
            const req = tx.objectStore(STORE_NAME).getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror = () => reject(req.error);
        });
    } finally {
        db.close();
    }
}
