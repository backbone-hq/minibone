import {
  decryptData,
  encryptData,
  generateKeyBytes,
  loadDecryptionKey,
  loadEncryptionKey,
  deriveMasterKeyFromSecret,
  deriveMatryoshkaKeys,
  generateUUID
} from './core'

import { encodeCanonical } from './canonical'

import { encodeCbor, decodeCbor } from './cbor'

import {
  Serializable,
  Secret,
  BundleV0Key,
  BundleV0,
  Bundle,
  EnvelopeV0,
  Envelope,
  EncryptedV0,
  Encrypted
} from './types'

class Minibone {
  public revision: number
  public uid: string
  private keys: BundleV0Key[]

  private constructor(revision: number, uid: string, keys: BundleV0Key[]) {
    this.revision = revision
    this.uid = uid
    this.keys = keys
  }

  /**
   * Initializes minibone for a new user.
   */
  public static async create(): Promise<Minibone> {
    const uid = await generateUUID()
    const minibone = new Minibone(0, uid, [])
    await minibone.rotate()
    return minibone
  }

  /**
   * Safely merge minibone instances.
   */
  public static merge(first: Minibone, second: Minibone): Minibone {
    if (first.uid != second.uid) {
      throw new Error('Cannot merge Minibone instances with different IDs.')
    }

    const mergedRevision = Math.max(first.revision, second.revision) + 1
    const mergedKeys = new Map(first.keys.map((key) => [key.id, key]))

    for (const key of second.keys) {
      mergedKeys.set(key.id, mergedKeys.get(key.id) || key)
    }

    return new Minibone(mergedRevision, first.uid, Array.from(mergedKeys.values()))
  }

  /**
   * Loads a minibone from a previous save.
   */
  public static async load(payload: Uint8Array, secret: Secret, context?: Serializable[]): Promise<Minibone> {
    const envelope = decodeCbor(payload)

    if (!envelope.v0) {
      throw new Error('Unrecognised envelope payload')
    }

    const v0Envelope = envelope.v0

    const masterKey: Uint8Array = await deriveMasterKeyFromSecret(secret, context)
    const [rawBundleKey] = await deriveMatryoshkaKeys(masterKey, [32])
    const bundleKey: CryptoKey = await loadDecryptionKey(rawBundleKey)

    const encodedAssociatedData: Uint8Array = encodeCanonical([v0Envelope.revision])
    const encodedBundle: Uint8Array = await decryptData(
      v0Envelope.iv,
      v0Envelope.ciphertext,
      bundleKey,
      encodedAssociatedData
    )
    const bundle: Bundle = decodeCbor(encodedBundle)

    if (!bundle.v0) {
      throw new Error('Unrecognised bundle payload')
    }

    const v0Bundle: BundleV0 = bundle.v0
    return new Minibone(v0Envelope.revisionrevision, v0Bundle.uid, v0Bundle.keys)
  }

  /**
   * Save a minibone instance's state.
   */
  public async save(secret: Secret, context?: Serializable[]): Promise<Uint8Array> {
    const masterKey: Uint8Array = await deriveMasterKeyFromSecret(secret, context)
    const [rawBundleKey] = await deriveMatryoshkaKeys(masterKey, [32])
    const bundleKey: CryptoKey = await loadEncryptionKey(rawBundleKey)

    const v0Bundle: BundleV0 = {
      uid: this.uid,
      keys: this.keys
    }

    const bundle: Bundle = {
      v0: v0Bundle
    }

    const newRevision = this.revision + 1

    const encodedBundle: Uint8Array = encodeCbor(bundle)
    const encodedAssociatedData: Uint8Array = encodeCanonical([newRevision])
    const [bundleIv, bundleCiphertext] = await encryptData(encodedBundle, bundleKey, encodedAssociatedData)

    const v0Envelope: EnvelopeV0 = {
      revision: newRevision,
      iv: bundleIv,
      ciphertext: bundleCiphertext
    }

    const envelope: Envelope = {
      v0: v0Envelope
    }

    return encodeCbor(envelope)
  }

  /**
   * Rotates the current active encryption key.
   */
  public async rotate(): Promise<void> {
    const id = await generateUUID()
    const value = await generateKeyBytes()
    const key: BundleV0Key = { id, value }
    this.keys.push(key)
  }

  /**
   * Encrypts data using the latest key.
   */
  public async encrypt(data: any, associatedData?: any): Promise<Uint8Array> {
    const encodedData = encodeCbor(data)

    const key = this.latestKey()
    const encryptionKey = await loadEncryptionKey(key.value)

    const [iv, ciphertext] = await encryptData(encodedData, encryptionKey, associatedData && encodeCbor(associatedData))

    const encryptedV0: EncryptedV0 = { keyId: key.id, iv, ciphertext }
    const encrypted: Encrypted = { v0: encryptedV0 }
    return encodeCbor(encrypted)
  }

  /**
   * Decrypts the given ciphertext bundle using the appropriate key.
   */
  public async decrypt(payload: Uint8Array, associatedData?: any): Promise<any> {
    const encrypted: Encrypted = decodeCbor(payload)

    if (!encrypted.v0) {
      throw new Error('Unrecognised encrypted payload')
    }

    const encryptedV0: EncryptedV0 = encrypted.v0

    const key = this.getKey(encryptedV0.keyId)
    const decryptionKey = await loadDecryptionKey(key.value)

    const encodedData = await decryptData(
      encryptedV0.iv,
      encryptedV0.ciphertext,
      decryptionKey,
      associatedData && encodeCbor(associatedData)
    )

    return decodeCbor(encodedData)
  }

  private latestKey(): BundleV0Key {
    return this.keys[this.keys.length - 1]
  }

  private getKey(id: string): BundleV0Key {
    return this.keys.filter((key) => key.id === id)[0]
  }
}

export default Minibone
