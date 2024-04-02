import * as cbor from 'cbor-x'

const cborContext = new cbor.Encoder({
  useRecords: false,
  mapsAsObjects: true
})

export const encodeCbor = (data: any): Uint8Array => {
  return Uint8Array.from(cborContext.encode(data))
}

export const decodeCbor = (payload: Uint8Array): any => {
  return cborContext.decode(payload)
}
