import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import esbuild from 'rollup-plugin-esbuild'
import { terser } from 'rollup-plugin-terser'
import { dts } from 'rollup-plugin-dts'

export default [
  {
    input: 'src/index.ts',
    plugins: [
      esbuild(),
      resolve({
        preferBuiltins: true,
        browser: true
      }),
      commonjs(),
      terser()
    ],
    output: [
      {
        file: 'dist/bundle.js',
        format: 'esm'
      }
    ]
  },
  {
    input: 'src/index.ts',
    plugins: [dts()],
    output: {
      file: 'dist/bundle.d.ts',
      format: 'es',
    },
  }
]
