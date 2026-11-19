import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  equipements: (() => Promise.resolve([])) as () => Promise<unknown>,
}))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return {
    ...actual,
    parcService: {
      ...actual.parcService,
      getEquipements: () => mocks.equipements(),
      getLocalNetworkInfo: () => Promise.resolve({ local_ip: '10.9.9.5', subnet: '10.9.9.0/24', hostname: 'hote' }),
    },
  }
})

import { ParcPage } from './ParcPage'

describe('ParcPage : aucune donnée inventée', () => {
  beforeEach(() => {
    mocks.equipements = () => Promise.resolve([])
  })

  it('parc vide : état vide explicite, aucun équipement ni topologie fictifs', async () => {
    render(<ParcPage />)
    expect(await screen.findByTestId('parc-empty-state')).toHaveTextContent('Aucun équipement dans le parc')
    expect(screen.queryByText(/CORE-RTR-01|FW-EXT-02|DIST-SW-A|SRV-WEB-01/)).toBeNull()
  })

  it('affiche uniquement les équipements renvoyés par le serveur', async () => {
    mocks.equipements = () =>
      Promise.resolve([
        {
          id: 7, nom: 'SRV-REEL', type: 'Serveur', ip: '10.9.9.20', mac: null, os: 'Debian', groupe: 'Prod',
          firmware: null, score_sante: 92, uptime_secondes: 3600, statut_collecte: 'OK',
          derniere_collecte: new Date().toISOString(), cpu_percent: 10, ram_percent: 20,
          cis_status: null, cis_message: null, last_backup: null, active_alerts_count: 0,
        },
      ])
    render(<ParcPage />)
    expect((await screen.findAllByText('SRV-REEL')).length).toBeGreaterThan(0)
    expect(screen.queryByTestId('parc-empty-state')).toBeNull()
    expect(screen.queryByText(/CORE-RTR-01|FW-EXT-02/)).toBeNull()
  })
})
