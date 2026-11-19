import { describe, expect, it } from 'vitest'

const sources = import.meta.glob(['./**/*.ts', './**/*.tsx', '!./**/*.test.ts', '!./**/*.test.tsx'], {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>

const INTERDITS = [
  /simulateStress|simulateBruteforce|switchToRealNetworkOnly/,
  /INITIAL_EQUIPMENTS|TOPO_NODES|DEMO_PREDICTIVE_SERVERS|FINDINGS_DIST_SW/,
  /EMULATED_CLI|Emulation CLI/,
  /demo_mode|VITE_DEMO_MODE|Mode Simulation/,
  /Password2026/,
  /RGPD &amp; CIS READY|VLAN 999|Scikit-Learn\)/,
]

describe('code source du frontend : aucune donnée ni mode de démonstration', () => {
  it.each(INTERDITS.map(r => [String(r), r] as const))('motif interdit absent : %s', (_nom, motif) => {
    const fautifs = Object.entries(sources).filter(([, contenu]) => motif.test(contenu)).map(([f]) => f)
    expect(fautifs).toEqual([])
  })
})
