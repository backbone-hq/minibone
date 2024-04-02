import type { Serializable } from './types'

export function encodeCanonical(input: Serializable | Serializable[]): Uint8Array {
  const encoder = new TextEncoder()

  if (input === null) {
    return new Uint8Array([0x00])
  }

  if (typeof input === 'boolean') {
    return new Uint8Array([0x01, input ? 0x01 : 0x00])
  }

  if (typeof input === 'number') {
    if (!Number.isInteger(input) || input < 0 || input > 4294967295) {
      throw new Error('Input is not a 32-bit unsigned integer')
    }

    const header = new Uint8Array([0x02])
    const number = new Uint8Array(new Uint32Array([input]).buffer)
    return new Uint8Array([...header, ...number])
  }

  if (input instanceof Uint8Array) {
    if (input.length > 4294967295) {
      throw new Error('Uint8Array length exceeds 32-bit integer limit')
    }

    const header = new Uint8Array([0x10])
    const length = new Uint8Array(new Uint32Array([input.length]).buffer)
    return new Uint8Array([...header, ...length, ...input])
  }

  if (typeof input === 'string') {
    const encodedString = encoder.encode(input)

    if (encodedString.length > 4294967295) {
      throw new Error('String length exceeds 32-bit integer limit')
    }

    const header = new Uint8Array([0x11])
    const length = new Uint8Array(new Uint32Array([encodedString.length]).buffer)
    return new Uint8Array([...header, ...length, ...encodedString])
  }

  if (Array.isArray(input)) {
    const elements: Uint8Array[] = []

    for (const item of input) {
      elements.push(encodeCanonical(item))
    }

    const totalLength = elements.reduce((acc, el) => acc + el.length, 0)

    if (totalLength > 4294967295) {
      throw new Error('Array total encoded length exceeds 32-bit integer limit')
    }

    const header = new Uint8Array([0x20])
    const length = new Uint8Array(new Uint32Array([elements.length]).buffer)
    const elementsArray = Uint8Array.from(elements.flatMap((e) => Array.from(e)))
    return new Uint8Array([...header, ...length, ...elementsArray])
  }

  throw new Error('Unsupported type')
}
