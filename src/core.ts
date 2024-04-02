import isNode from 'detect-node'
const crypto = isNode ? require('crypto') : window.crypto

import type { Serializable, Secret } from './types'
import { encodeCanonical } from './canonical'

const ENCRYPTION_ALGORITHM = {
  name: 'AES-GCM',
  tagLength: 128
}

const HASH_ALGORITHM = {
  hash: 'SHA-256'
}

const KEY_DERIVATION_ALGORITHM = {
  name: 'HKDF'
}

const PASSWORD_HASHING_ALGORITHM = {
  name: 'PBKDF2',
  iterations: 500_000
}

export const generateRandomBytes = (length: number): Uint8Array => {
  if (isNode) {
    return crypto.randomBytes(length)
  } else {
    const buffer = new Uint8Array(length)
    crypto.getRandomValues(buffer)
    return buffer
  }
}

export const generateUUID = async () => {
  const bytes = generateRandomBytes(16)
  return [...bytes]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-4$3-$4-$5')
}

export const generateKeyBytes = async (): Promise<Uint8Array> => {
  return new Uint8Array(generateRandomBytes(32))
}

export const loadEncryptionKey = async (keyData: Uint8Array): Promise<CryptoKey> => {
  return await crypto.subtle.importKey('raw', keyData, ENCRYPTION_ALGORITHM, false, ['encrypt'])
}

export const loadDecryptionKey = async (keyData: Uint8Array): Promise<CryptoKey> => {
  return await crypto.subtle.importKey('raw', keyData, ENCRYPTION_ALGORITHM, false, ['decrypt'])
}

export const encryptData = async (
  data: Uint8Array,
  key: CryptoKey,
  associatedData?: Uint8Array
): Promise<[Uint8Array, Uint8Array]> => {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const buffer = await crypto.subtle.encrypt({ ...ENCRYPTION_ALGORITHM, iv, additionalData: associatedData }, key, data)
  return [iv, new Uint8Array(buffer)]
}

export const decryptData = async (
  iv: Uint8Array,
  ciphertext: Uint8Array,
  key: CryptoKey,
  associatedData?: Uint8Array
): Promise<Uint8Array> => {
  const buffer = await crypto.subtle.decrypt(
    { ...ENCRYPTION_ALGORITHM, iv, additionalData: associatedData },
    key,
    ciphertext
  )
  return new Uint8Array(buffer)
}

async function deriveKey(key: Uint8Array, outputLength: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey('raw', key, KEY_DERIVATION_ALGORITHM, false, ['deriveBits'])

  const derivedBits = await crypto.subtle.deriveBits(
    {
      ...KEY_DERIVATION_ALGORITHM,
      ...HASH_ALGORITHM,
      info: new Uint8Array(),
      salt: new Uint8Array()
    },
    keyMaterial,
    outputLength * 8
  )

  return new Uint8Array(derivedBits)
}

export async function deriveMatryoshkaKeys(masterKey: Uint8Array, outputLengths: number[]): Promise<Uint8Array[]> {
  let secretState = masterKey
  const secretStateLength = secretState.length
  const outputs: Uint8Array[] = []

  for (const outputLength of outputLengths) {
    const extendedOutputLength = secretStateLength + outputLength
    const derivedBytes = await deriveKey(secretState, extendedOutputLength)

    const newSecretMaterial = derivedBytes.slice(0, secretStateLength)
    const derivedValue = derivedBytes.slice(secretStateLength, secretStateLength + outputLength)

    secretState = newSecretMaterial
    outputs.push(derivedValue)
  }

  return outputs
}

export const deriveMasterKeyFromSecret = async (
  secret: Secret,
  pv?: Serializable | Serializable[]
): Promise<Uint8Array> => {
  const encodedSecret: Uint8Array = encodeCanonical(secret)
  const encodedPv: Uint8Array = pv === undefined ? new Uint8Array() : encodeCanonical(pv)

  const importedKey = await crypto.subtle.importKey('raw', encodedSecret, PASSWORD_HASHING_ALGORITHM, false, [
    'deriveBits'
  ])

  const derivedKeyBuffer = await crypto.subtle.deriveBits(
    {
      ...PASSWORD_HASHING_ALGORITHM,
      ...HASH_ALGORITHM,
      salt: encodedPv
    },
    importedKey,
    256
  )

  return new Uint8Array(derivedKeyBuffer)
}
