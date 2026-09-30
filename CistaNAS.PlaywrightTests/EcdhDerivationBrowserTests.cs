using System.Security.Cryptography;
using System.Text.Json;
using CistaNAS.Shared.Crypto;

namespace CistaNAS.PlaywrightTests;

/// <summary>
/// browser e2ee.js の決定論的 ECDH identity 導出が C# EcdhIdentityKey と
/// バイト等価であることを実ブラウザで検証する（固定入力 → 同一公開鍵）。
/// </summary>
[Collection("Playwright")]
public class EcdhDerivationBrowserTests(PlaywrightWebAppFixture fixture)
{
    private const string Username = "alice";
    private const string Password = "s3cret-pass";
    /// <summary>0x00..0x1F の 32 バイト固定 salt（base64）。C# 側の FixedSalt と同一バイト列。</summary>
    private const string SaltB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    /// <summary>C# 側（EcdhIdentityKey.DeriveKeyPair）で同一入力から導出した公開鍵。</summary>
    private static string DeriveCsharpPublicKey(string algorithm)
    {
        var spec = algorithm == "pbkdf2-sha256"
            ? new KdfSpec("pbkdf2-sha256", 10000, 0, 0, 0)
            : new KdfSpec(algorithm, 1000, 8192, 2, 1);
        byte[] salt = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(Username, Password, salt, spec);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(priv);
        return Convert.ToBase64String(pub);
    }

    [Theory]
    [InlineData("argon2id")]
    [InlineData("pbkdf2-sha256")]
    public async Task JsDeriveIdentityKeyPair_MatchesCsharpPublicKey(string algorithm)
    {
        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();

        // モジュール import と hash-wasm（globalThis.hashwasm）をロードするためアプリを開く
        await page.GotoAsync(fixture.BaseUrl);

        var jsResult = await page.EvaluateAsync<JsonElement>(@"(async (args) => {
            const m = await import('./js/e2ee.js');
            const salt = args.salt;
            const composite = await m.deriveIdentityKeyPair('alice', 's3cret-pass', salt,
                { algorithm: 'argon2id', iterations: 1000, memoryKiB: 8192, timeCost: 1, parallelism: 2 });
            const legacy = await m.deriveIdentityKeyPair('alice', 's3cret-pass', salt,
                { algorithm: 'pbkdf2-sha256', iterations: 10000, memoryKiB: 0, timeCost: 0, parallelism: 0 });
            const normalized = await m.deriveIdentityKeyPair('  Alice ', 's3cret-pass', salt,
                { algorithm: 'argon2id', iterations: 1000, memoryKiB: 8192, timeCost: 1, parallelism: 2 });
            return {
                composite: composite.publicKeyBase64,
                legacy: legacy.publicKeyBase64,
                normalized: normalized.publicKeyBase64,
            };
        })", new { salt = SaltB64 });

        // username 正規化（Trim + 小文字化）を含め C# とバイト等価
        Assert.Equal(DeriveCsharpPublicKey("argon2id"), jsResult.GetProperty("composite").GetString());
        Assert.Equal(DeriveCsharpPublicKey("argon2id"), jsResult.GetProperty("normalized").GetString());
        Assert.Equal(DeriveCsharpPublicKey("pbkdf2-sha256"), jsResult.GetProperty("legacy").GetString());
    }

    /// <summary>
    /// ECDH identity 導出後もブラウザストレージ（localStorage / sessionStorage）に
    /// 秘密鍵が一切永続化されないこと（項目 6 の WASM 分）。
    /// 旧バージョンの残留キー名 (e2ee_privkey_* / ecdh_priv*) に加え、導出した秘密鍵の
    /// 生バイトが値として書き出されないことも合わせて検証する。
    /// 公開鍵 pin は IndexedDB に fingerprint (SHA-256) のみを保存するため秘密鍵に該当しない。
    /// </summary>
    [Fact]
    public async Task IdentityDerivation_NeverPersistsPrivateKeyToBrowserStorage()
    {
        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();

        // モジュール import（e2ee.js）のためアプリを開く
        await page.GotoAsync(fixture.BaseUrl);

        var jsResult = await page.EvaluateAsync<JsonElement>(@"(async (args) => {
            const m = await import('./js/e2ee.js');
            const kp = await m.deriveIdentityKeyPair('alice', 's3cret-pass', args.salt,
                { algorithm: 'pbkdf2-sha256', iterations: 10000, memoryKiB: 0, timeCost: 0, parallelism: 0 });
            try {
                // 導出直後の状態でストレージをスキャンする（クリーンアップ前に採取）
                const scanKeys = (storage) => {
                    const hits = [];
                    for (let i = 0; i < storage.length; i++) {
                        const k = storage.key(i);
                        if (k && /priv|secret|ecdh/i.test(k)) hits.push(k);
                    }
                    return hits;
                };
                const scanValues = (storage) => {
                    // 値にも秘密鍵の生バイト（base64 断片）が書き出されていないこと
                    const hits = [];
                    for (let i = 0; i < storage.length; i++) {
                        const k = storage.key(i);
                        if (!k) continue;
                        const v = storage.getItem(k) ?? '';
                        if (v.includes(args.privSample)) hits.push(k);
                    }
                    return hits;
                };
                return {
                    localKeys: scanKeys(localStorage),
                    sessionKeys: scanKeys(sessionStorage),
                    localValues: scanValues(localStorage),
                    sessionValues: scanValues(sessionStorage),
                    pubB64: kp.publicKeyBase64,
                };
            } finally {
                m.clearKey(kp.privateKeyHandle);
                m.clearKey(kp.publicKeyHandle);
            }
        })", new
        {
            salt = SaltB64,
            // C# 側で実導出した秘密鍵の生バイト断片（base64 部分一致サンプル）。
            // 導出結果が正しい前提で、そのバイト列がストレージの値に書き出されていないことを検証する
            privSample = SamplePrivateKeyB64(),
        });

        Assert.Empty(jsResult.GetProperty("localKeys").EnumerateArray());
        Assert.Empty(jsResult.GetProperty("sessionKeys").EnumerateArray());
        Assert.Empty(jsResult.GetProperty("localValues").EnumerateArray());
        Assert.Empty(jsResult.GetProperty("sessionValues").EnumerateArray());

        // 導出自体は C# と一致していること（このテストが有効な導出であることの保証）
        Assert.Equal(DeriveCsharpPublicKey("pbkdf2-sha256"), jsResult.GetProperty("pubB64").GetString());
    }

    /// <summary>実導出した秘密鍵の一部（base64 断片）を取得する（値スキャン用サンプル）。</summary>
    private static string SamplePrivateKeyB64()
    {
        byte[] salt = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var (_, priv) = EcdhIdentityKey.DeriveKeyPair(
            Username, Password, salt, new KdfSpec("pbkdf2-sha256", 10000, 0, 0, 0));
        try
        {
            // 秘密鍵 32 バイトの先頭 16 バイト分の base64 断片（連続一致する部分列）
            return Convert.ToBase64String(priv, 0, 15)[..^2]; // padding 除去で部分一致可能に
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(priv);
        }
    }

    /// <summary>導出した identity 秘密鍵で ECIES アンラップができること（C# ラップ ↔ JS アンラップ）。</summary>
    [Fact]
    public async Task DerivedKey_EciesInterop_CsharpWrapJsUnwrap()
    {
        await using var context = await fixture.CreateAnonymousContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl);

        // C# 側で identity 鍵を導出し、その公開鍵で masterKey を ECIES ラップ
        byte[] salt = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(
            Username, Password, salt, new KdfSpec("pbkdf2-sha256", 10000, 0, 0, 0));
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(priv);
        byte[] masterKey = E2eeCrypto.GenerateMasterKey();
        byte[] masterKeyCopy = (byte[])masterKey.Clone();
        var (ephPub, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, pub);
        CryptographicOperations.ZeroMemory(masterKey);

        // ecdhUnwrap は CryptoKey handle を返すため、アンラップ鍵でチャンク暗号化し
        // C# 側で既知の masterKey から復号できることで一致を検証する
        string encChunk = await page.EvaluateAsync<string>(@"(async (args) => {
            const m = await import('./js/e2ee.js');
            const kp = await m.deriveIdentityKeyPair('alice', 's3cret-pass', args.salt,
                { algorithm: 'pbkdf2-sha256', iterations: 10000, memoryKiB: 0, timeCost: 0, parallelism: 0 });
            // JS 導出の公開鍵が C# 導出と一致すること
            if (kp.publicKeyBase64 !== args.pub) throw new Error('public key mismatch: ' + kp.publicKeyBase64);
            const masterHandle = await m.ecdhUnwrap(args.nonce, args.ct, args.tag, args.eph, kp.privateKeyHandle);
            m.clearKey(kp.privateKeyHandle);
            m.clearKey(kp.publicKeyHandle);
            try {
                return await m.encryptChunk('dGVzdA==', masterHandle, 0, args.fileSalt, true, 1);
            } finally {
                m.clearKey(masterHandle);
            }
        })", new
        {
            salt = SaltB64,
            pub = Convert.ToBase64String(pub),
            eph = Convert.ToBase64String(ephPub),
            nonce = Convert.ToBase64String(nonce),
            ct = Convert.ToBase64String(ct),
            tag = Convert.ToBase64String(tag),
            fileSalt = "AAAAAAAAAAAAAAAAAAAAAA==",
        });

        // C# 側で既知の masterKey から復号できる（= アンラップされた鍵が一致）
        byte[] encData = Convert.FromBase64String(encChunk);
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKeyCopy, Enumerable.Repeat((byte)0, 16).ToArray());
        byte[] plain = E2eeCrypto.DecryptChunk(encData, fileKey, 0, out _, revision: 1);
        CryptographicOperations.ZeroMemory(fileKey);
        Assert.Equal("test"u8.ToArray(), plain);
        CryptographicOperations.ZeroMemory(masterKeyCopy);
    }
}
