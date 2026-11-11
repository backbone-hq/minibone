import assert from 'node:assert/strict'
import Minibone from 'minibone'

const data = { message: 'Package smoke test' }
const minibone = await Minibone.create()
const ciphertext = await minibone.encrypt(data)
const payload = await minibone.save('test-secret', ['package-test'])
const loaded = await Minibone.load(payload, 'test-secret', ['package-test'])

assert.deepEqual(await loaded.decrypt(ciphertext), data)
