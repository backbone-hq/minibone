import { TextEncoder, TextDecoder } from 'util'
Object.assign(global, { TextEncoder, TextDecoder })

import Minibone from '../src'
import { encodeCanonical } from '../src/canonical'
import { encodeCbor, decodeCbor } from '../src/cbor'

const data = {
  number: 1337,
  string: 'Hello, minibone!',
  array: ['Backbone', 0],
  bytes: new Uint8Array([6, 9, 4, 2, 0])
}

describe('Minibone', () => {
  test('can encrypt and decrypt values', async () => {
    const minibone = await Minibone.create()
    const ciphertext = await minibone.encrypt(data)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('rotation results in key change', async () => {
    const minibone = await Minibone.create()
    const olderCiphertext = await minibone.encrypt(data)
    await minibone.rotate()
    const newerCiphertext = await minibone.encrypt(data)

    const olderResult = decodeCbor(olderCiphertext)
    const newerResult = decodeCbor(newerCiphertext)
    expect(olderResult.v0.keyId).not.toEqual(newerResult.v0.keyId)
  })

  test('can decrypt post rotation', async () => {
    const minibone = await Minibone.create()
    const ciphertext = await minibone.encrypt(data)
    await minibone.rotate()
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('profiles can be exported and imported', async () => {
    const minibone = await Minibone.create()
    const ciphertext = await minibone.encrypt(data)

    for (const context of [['test'], undefined]) {
      const exported = await minibone.save('minibone-secure-phrase', context)
      const miniboneImported = await Minibone.load(exported, 'minibone-secure-phrase', context)
      await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
    }
  })

  test('can be safely merged', async () => {
    const mainMinibone = await Minibone.create()

    const oldCiphertext = await mainMinibone.encrypt(data)
    const exportedOldMinibone = await mainMinibone.save('minibone-secure-phrase', ['test'])

    // `mainMinibone` is now out of date with `exportedOldMinibone`
    await mainMinibone.rotate()
    const mainCipherText = await mainMinibone.encrypt(data)

    // `branchedMinibone` and `mainMinibone` both now have unsynchronized keys
    const branchedMinibone = await Minibone.load(exportedOldMinibone, 'minibone-secure-phrase', ['test'])
    await branchedMinibone.rotate()
    const branchedCiphertext = await branchedMinibone.encrypt(data)

    // Expectations pre-merge
    await expect(mainMinibone.decrypt(oldCiphertext)).resolves.toEqual(data)
    await expect(mainMinibone.decrypt(mainCipherText)).resolves.toEqual(data)
    await expect(mainMinibone.decrypt(branchedCiphertext)).rejects.toThrow()

    await expect(branchedMinibone.decrypt(oldCiphertext)).resolves.toEqual(data)
    await expect(branchedMinibone.decrypt(mainCipherText)).rejects.toThrow()
    await expect(branchedMinibone.decrypt(branchedCiphertext)).resolves.toEqual(data)

    // Expectations post-merge
    const mergedMinibone = Minibone.merge(mainMinibone, branchedMinibone)
    await expect(mergedMinibone.decrypt(oldCiphertext)).resolves.toEqual(data)
    await expect(mergedMinibone.decrypt(mainCipherText)).resolves.toEqual(data)
    await expect(mergedMinibone.decrypt(branchedCiphertext)).resolves.toEqual(data)
  })

  test('throws an error when trying to decrypt with an invalid key', async () => {
    const minibone = await Minibone.create()
    const ciphertext = await minibone.encrypt(data)
    await minibone.rotate()
    await minibone.rotate()
    await expect(minibone.decrypt(ciphertext, { keyId: '1234' })).rejects.toThrow()
  })

  test('can encrypt and decrypt empty objects', async () => {
    const minibone = await Minibone.create()
    const emptyObject = {}
    const ciphertext = await minibone.encrypt(emptyObject)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(emptyObject)
  })

  test('can encrypt and decrypt null values', async () => {
    const minibone = await Minibone.create()
    const nullValue = null
    const ciphertext = await minibone.encrypt(nullValue)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(nullValue)
  })

  test('can encrypt and decrypt boolean values', async () => {
    const minibone = await Minibone.create()
    const booleanValue = true
    const ciphertext = await minibone.encrypt(booleanValue)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(booleanValue)
  })

  test('can encrypt and decrypt nested objects', async () => {
    const minibone = await Minibone.create()
    const nestedObject = { a: { b: { c: 'nested' } } }
    const ciphertext = await minibone.encrypt(nestedObject)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(nestedObject)
  })

  test('throws an error when trying to decrypt invalid ciphertext', async () => {
    const minibone = await Minibone.create()
    const invalidCiphertext = new Uint8Array([1, 2, 3])
    await expect(minibone.decrypt(invalidCiphertext)).rejects.toThrow()
  })

  test('can encrypt and decrypt with associated data', async () => {
    const minibone = await Minibone.create()
    const associatedData = { context: 'test' }
    const ciphertext = await minibone.encrypt(data, associatedData)
    await expect(minibone.decrypt(ciphertext, associatedData)).resolves.toEqual(data)
  })

  test('throws an error when decrypting with incorrect associated data', async () => {
    const minibone = await Minibone.create()
    const associatedData = { context: 'test' }
    const ciphertext = await minibone.encrypt(data, associatedData)
    const incorrectAssociatedData = { context: 'incorrect' }
    await expect(minibone.decrypt(ciphertext, incorrectAssociatedData)).rejects.toThrow()
  })

  test('can encrypt and decrypt large payloads', async () => {
    const minibone = await Minibone.create()
    const largeData = new Uint8Array(1024 * 1024) // 1 MB
    const ciphertext = await minibone.encrypt(largeData)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(largeData)
  })

  test('throws an error when trying to decrypt with a different secret', async () => {
    const minibone = await Minibone.create()
    const exported = await minibone.save('minibone-secure-phrase', ['test'])
    await expect(Minibone.load(exported, 'different-secure-phrase', ['test'])).rejects.toThrow()
  })

  test('throws an error when trying to decrypt with a different context', async () => {
    const minibone = await Minibone.create()
    const exported = await minibone.save('minibone-secure-phrase', ['test'])
    await expect(Minibone.load(exported, 'minibone-secure-phrase', ['different-context'])).rejects.toThrow()
  })

  test('can encrypt and decrypt with empty associated data', async () => {
    const minibone = await Minibone.create()
    const emptyAssociatedData = {}
    const ciphertext = await minibone.encrypt(data, emptyAssociatedData)
    await expect(minibone.decrypt(ciphertext, emptyAssociatedData)).resolves.toEqual(data)
  })

  test('throws an error when trying to merge instances with different IDs', async () => {
    const minibone1 = await Minibone.create()
    const minibone2 = await Minibone.create()
    expect(() => Minibone.merge(minibone1, minibone2)).toThrow()
  })

  test('can encrypt and decrypt values with special characters', async () => {
    const minibone = await Minibone.create()
    const specialCharData = { message: '!@#$%^&*()_+{}[]|\\:;"<>,.?/' }
    const ciphertext = await minibone.encrypt(specialCharData)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(specialCharData)
  })

  test('can encrypt and decrypt empty strings', async () => {
    const minibone = await Minibone.create()
    const emptyString = ''
    const ciphertext = await minibone.encrypt(emptyString)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(emptyString)
  })

  test('can encrypt and decrypt strings with Unicode characters', async () => {
    const minibone = await Minibone.create()
    const unicodeString = '你好，世界！'
    const ciphertext = await minibone.encrypt(unicodeString)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(unicodeString)
  })

  test('can encrypt and decrypt arrays with mixed data types', async () => {
    const minibone = await Minibone.create()
    const mixedArray = [1, 'hello', true, null, { key: 'value' }]
    const ciphertext = await minibone.encrypt(mixedArray)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(mixedArray)
  })

  test('throws an error when trying to encrypt non-serializable values', async () => {
    const minibone = await Minibone.create()
    const nonSerializableValue = () => {}
    await expect(minibone.encrypt(nonSerializableValue)).rejects.toThrow()
  })

  test('can encrypt and decrypt extremely long strings', async () => {
    const minibone = await Minibone.create()
    const longString = 'a'.repeat(1024 * 1024) // 1 MB string
    const ciphertext = await minibone.encrypt(longString)
    await expect(minibone.decrypt(ciphertext)).resolves.toEqual(longString)
  })

  test('can encrypt and decrypt with empty context', async () => {
    const minibone = await Minibone.create()
    const ciphertext = await minibone.encrypt(data)
    const exported = await minibone.save('minibone-secure-phrase', [])
    const miniboneImported = await Minibone.load(exported, 'minibone-secure-phrase', [])
    await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('can encrypt and decrypt with empty context', async () => {
    const minibone = await Minibone.create()
    const ciphertext = await minibone.encrypt(data)
    const exported = await minibone.save('minibone-secure-phrase', [])
    const miniboneImported = await Minibone.load(exported, 'minibone-secure-phrase', [])
    await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('can encrypt and decrypt with extremely long context', async () => {
    const minibone = await Minibone.create()
    const longContext = ['a'.repeat(1024 * 1024)] // 1 MB context
    const ciphertext = await minibone.encrypt(data)
    const exported = await minibone.save('minibone-secure-phrase', longContext)
    const miniboneImported = await Minibone.load(exported, 'minibone-secure-phrase', longContext)
    await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('can encrypt and decrypt with extremely long context', async () => {
    const minibone = await Minibone.create()
    const longContext = ['a'.repeat(1024 * 1024)] // 1 MB context
    const ciphertext = await minibone.encrypt(data)
    const exported = await minibone.save('minibone-secure-phrase', longContext)
    const miniboneImported = await Minibone.load(exported, 'minibone-secure-phrase', longContext)
    await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('can encrypt and decrypt with non-ASCII characters in context', async () => {
    const minibone = await Minibone.create()
    const nonASCIIContext = ['你好，世界！']
    const ciphertext = await minibone.encrypt(data)
    const exported = await minibone.save('minibone-secure-phrase', nonASCIIContext)
    const miniboneImported = await Minibone.load(exported, 'minibone-secure-phrase', nonASCIIContext)
    await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('can encrypt and decrypt with special characters in context', async () => {
    const minibone = await Minibone.create()
    const specialCharContext = ['!@#$%^&*()_+{}[]|\\:;"<>,.?/']
    const ciphertext = await minibone.encrypt(data)
    const exported = await minibone.save('minibone-secure-phrase', specialCharContext)
    const miniboneImported = await Minibone.load(exported, 'minibone-secure-phrase', specialCharContext)
    await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('can encrypt and decrypt with extremely short secrets', async () => {
    const minibone = await Minibone.create()
    const shortSecret = 'a'
    const ciphertext = await minibone.encrypt(data)
    const exported = await minibone.save(shortSecret, ['test'])
    const miniboneImported = await Minibone.load(exported, shortSecret, ['test'])
    await expect(miniboneImported.decrypt(ciphertext)).resolves.toEqual(data)
  })

  test('encodes null correctly', () => {
    const encoded = encodeCanonical(null)
    expect(encoded).toEqual(new Uint8Array([0x00]))
  })

  test('encodes true correctly', () => {
    const encoded = encodeCanonical(true)
    expect(encoded).toEqual(new Uint8Array([0x01, 0x01]))
  })

  test('encodes false correctly', () => {
    const encoded = encodeCanonical(false)
    expect(encoded).toEqual(new Uint8Array([0x01, 0x00]))
  })

  test('encodes a 32-bit unsigned integer correctly', () => {
    const encoded = encodeCanonical(1234567890)
    expect(encoded).toEqual(new Uint8Array([0x02, 0xd2, 0x02, 0x96, 0x49]))
  })

  test('throws an error when encoding a negative integer', () => {
    expect(() => encodeCanonical(-1)).toThrow('Input is not a 32-bit unsigned integer')
  })

  test('throws an error when encoding a non-integer number', () => {
    expect(() => encodeCanonical(3.14)).toThrow('Input is not a 32-bit unsigned integer')
  })

  test('throws an error when encoding a number greater than 2^32 - 1', () => {
    expect(() => encodeCanonical(4294967296)).toThrow('Input is not a 32-bit unsigned integer')
  })

  test('encodes a Uint8Array correctly', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const encoded = encodeCanonical(data)
    expect(encoded).toEqual(new Uint8Array([0x10, 0x05, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5]))
  })

  test('throws an error when encoding a Uint8Array with length greater than 2^32 - 1', () => {
    const largeData = new Uint8Array(4294967296)
    expect(() => encodeCanonical(largeData)).toThrow('Uint8Array length exceeds 32-bit integer limit')
  })

  test('encodes an array of mixed types correctly', () => {
    const data = [null, true, 42, new Uint8Array([1, 2, 3]), 'hello']
    const encoded = encodeCanonical(data)
    expect(encoded).toEqual(
      new Uint8Array([
        0x20, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x2a, 0x00, 0x00, 0x00, 0x10, 0x03, 0x00, 0x00, 0x00, 1,
        2, 3, 0x11, 0x05, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f
      ])
    )
  })

  test('throws an error when encoding a negative number', () => {
    expect(() => encodeCanonical(-1)).toThrow('Input is not a 32-bit unsigned integer')
  })

  test('throws an error when encoding a number greater than 4294967295', () => {
    expect(() => encodeCanonical(4294967296)).toThrow('Input is not a 32-bit unsigned integer')
  })

  test('throws an error when encoding a Uint8Array exceeding the 32-bit integer limit', () => {
    const largeUint8Array = new Uint8Array(4294967296)
    expect(() => encodeCanonical(largeUint8Array)).toThrow('Uint8Array length exceeds 32-bit integer limit')
  })

  test('throws an error when loading with an unrecognized envelope payload', async () => {
    const invalidEnvelope = { invalid: true }
    const encodedInvalidEnvelope = encodeCbor(invalidEnvelope)
    await expect(Minibone.load(encodedInvalidEnvelope, 'minibone-secure-phrase', ['test'])).rejects.toThrow(
      'Unrecognised envelope payload'
    )
  })

  test('throws an error when loading with an unrecognized bundle payload', async () => {
    const invalidBundle = { invalid: true, padding: 'abcdefghijklmnopqrstuvwxyz' }
    const encodedInvalidBundle = encodeCbor(invalidBundle)
    const envelope = {
      v0: {
        revision: 1,
        iv: new Uint8Array(12),
        ciphertext: encodedInvalidBundle
      }
    }
    const encodedEnvelope = encodeCbor(envelope)
    await expect(Minibone.load(encodedEnvelope, 'minibone-secure-phrase', ['test'])).rejects.toThrow(
      'The operation failed for an operation-specific reason'
    )
  })

  test('throws an error when decrypting with an unrecognized encrypted payload', async () => {
    const minibone = await Minibone.create()
    const invalidEncrypted = { invalid: true }
    const encodedInvalidEncrypted = encodeCbor(invalidEncrypted)
    await expect(minibone.decrypt(encodedInvalidEncrypted)).rejects.toThrow('Unrecognised encrypted payload')
  })
})
