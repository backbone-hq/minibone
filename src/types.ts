export type Secret = string | Uint8Array
export type Serializable = null | boolean | Uint8Array | string | number

export interface EnvelopeV0 {
  revision: number
  iv: Uint8Array
  ciphertext: Uint8Array
}

export interface Envelope {
  v0?: EnvelopeV0
}

export interface BundleV0Key {
  id: string
  value: Uint8Array
}

export interface BundleV0 {
  uid: string
  keys: BundleV0Key[]
}

export interface Bundle {
  v0?: BundleV0
}

export interface EncryptedV0 {
  keyId: string
  iv: Uint8Array
  ciphertext: Uint8Array
}

export interface Encrypted {
  v0?: EncryptedV0
}
