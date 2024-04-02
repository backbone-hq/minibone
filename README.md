# ![Minibone](https://github.com/backbone-hq/minibone/blob/master/media/minibone.png?raw=true)

![Build Status](https://img.shields.io/github/actions/workflow/status/backbone-hq/minibone/main.yml?branch=master)
![GitHub License](https://img.shields.io/github/license/backbone-hq/minibone)
![NPM Version](https://img.shields.io/npm/v/minibone?logo=npm)
![Made by Backbone](https://img.shields.io/badge/made_by-backbone-blue)

Minibone is a compact, versatile, and misuse-resistant library designed to make incorporating end-to-end encryption in your applications **remarkably simple**. It allows you to store and manage your users' sensitive data while ensuring that only the users themselves can access and decrypt the information — helping you minimize the blast radius of breaches, meet compliance requirements, enhance privacy, and build trust.

Building _secure-by-design_ applications is _hard_. Minibone makes it _practical_.

### 🏗️ Background

Minibone is built atop the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). It's restricted to a _conservative_ suite of symmetric algorithms for quantum resistance and robustness.

Specifically, Minibone uses `AES-GCM-256` for encryption, `HKDF-SHA-256` for key derivation, and `PBKDF2-SHA-256` with 500,000 iterations for password-based key derivation. Minibone also opts to keep its dependencies to the bare minimum to reduce the risk of supply-chain attacks.

### ☢️ Threat Model

Minibone is designed to run on a `client` device (e.g., your desktop, mobile, or web-based app), storing data with a `provider` (e.g., a SaaS platform) through a `communication channel` (e.g., HTTPS). In this scenario, Minibone is designed to assure confidentiality and integrity, but not availability [1] or freshness [2], when the `provider` and/or the `communication channel` are compromised.

We assume that the client application and device are not compromised and not otherwise vulnerable to side-channel attacks.

1. A malicious `provider` could selectively delete data they store.
   A compromised `communication channel` could selectively drop messages based on metadata.
2. A malicious `provider` could selectively revert data to earlier versions.
   A compromised `communication channel` could replay messages associated with earlier versions.

### 💾 Installation

Minibone is hosted on [NPM](https://www.npmjs.com/package/minibone). 
You can add it to your project by running the `npm` command below or an equivalent command in your package manager.

```bash
npm i minibone
```

### 📇 Usage

```typescript
import Minibone from 'minibone'

// Define a unique service identifier
const serviceIdentifier: any = 'my-unique-service-identifier'

// Virtual API, communication channel and storage provider
class Backend {
    private userBundles: Map<string, Uint8Array> = new Map()
    private dataBundles: Map<string, Uint8Array> = new Map()

    registerUser = async (uid: string, bundle: Uint8Array): Promise<void> => {this.userBundles.set(uid, bundle)}
    fetchUser = async (uid: string): Promise<Uint8Array> => this.userBundles.get(uid) ?? new Uint8Array()
    putData = async (uid: string, data: Uint8Array): Promise<void> => {this.dataBundles.set(uid, data)}
    fetchData = async (uid: string): Promise<Uint8Array> => this.dataBundles.get(uid) ?? new Uint8Array()
}
const virtualBackend = new Backend();

// Register a user; initialize their minibone instance
const minibone: Minibone = await Minibone.create()

// Encrypt and send the user's minibone to the provider
const userName: any = 'some-unique-user-name'
const payload: Uint8Array = await minibone.save('secure-user-secret', [serviceIdentifier, userName])
await virtualBackend.registerUser(userName, payload)

// Encrypt user data
const data: any = {
    sq6wmgv2zcsrix6t: 'BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION.',
}
const encrypted: Uint8Array = await minibone.encrypt(data)
await virtualBackend.putData(minibone.uid, encrypted)

// Fetch and load the user's minibone. You probably want to guard payload retrieval behind multi-factor authentication in production.
const payload: Uint8Array = await virtualBackend.fetchUser(userName)
const loadedMinibone: Minibone = await Minibone.load(payload, 'secure-user-secret', [serviceIdentifier, userName])

// Decrypt data using the reconstructed minibone
const fetched: Uint8Array = await virtualBackend.fetchData(minibone.uid)
const decryptedData: any = await loadedMinibone.decrypt(fetched)
```

### ⚠ Caveats

Minibone is designed to be simple to use and difficult to abuse. That said, there are a few important aspects to keep in mind when interfacing with Minibone.

1. It's important for the context vector (the second parameter of `minibone.save` and third parameter of `Minibone.load`) to be _globally_ unique to reduce the risk of key reuse and maximize the marginal cost of [rainbow table](https://en.wikipedia.org/wiki/Rainbow_table) attacks.
2. When prompting end users for a passphrase or master secret, this secret **must** remain client-side. We recommend using a battle-tested password strength estimator (e.g., [zxcvbn](https://github.com/dropbox/zxcvbn)). **User secrets should be deleted immediately after use** to make it just that bit harder for attackers.

### 🧩 Limitations
Minibone relies _solely_ on symmetric cryptography. While this makes it robust against a number of contemporary and future attacks, it also makes data sharing, assured identity, access control, and real-time collaborative workflows infeasible to implement.

Minibone's enterprise counterpart, [Backbone](https://backbone.dev), was designed from first principles to support complex multi-user, multi-enterprise workflows under total end-to-end encryption with a stricter threat model.

If these are a priority, reach out to us by emailing us at [root@backbone.dev](mailto:root@backbone.dev).

---

Built with 🦴 by [Backbone](https://backbone.dev)
