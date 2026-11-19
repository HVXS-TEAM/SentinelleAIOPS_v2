import { render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Fonctions simples (pas des espions vi.fn) : un espion rattache un .then au rejet, vu comme non géré.
const mocks = vi.hoisted(() => ({
  devices: (() => Promise.resolve([])) as () => Promise<unknown>,
  audit: (() => Promise.resolve({ violations: [], score: 100 })) as () => Promise<unknown>,
  backups: (() => Promise.resolve([])) as () => Promise<unknown>,
}))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return {
    ...actual,
    netdevopsService: {
      ...actual.netdevopsService,
      getDevices: () => mocks.devices(),
      runAudit: () => mocks.audit(),
      getBackups: () => mocks.backups(),
    },
  }
})

import { NetDevOpsPage } from './NetDevOpsPage'

describe('NetDevOpsPage : aucune donnée inventée', () => {
  beforeEach(() => {
    mocks.devices = () => Promise.resolve([])
    mocks.audit = () => Promise.resolve({ violations: [], score: 100 })
    mocks.backups = () => Promise.resolve([])
  })

  it('parc vide : message explicite, aucun équipement fictif', async () => {
    render(<NetDevOpsPage />)
    expect(await screen.findByTestId('netdevops-no-devices')).toBeInTheDocument()
    expect(screen.queryByText(/SW-CORE-01|RTR-EDGE-01|FW-PERIMETER-01|AP-WIFI-01/)).toBeNull()
    expect(screen.getByTestId('netdevops-no-selection')).toBeInTheDocument()
  })

  it("équipement jamais audité : score N/A et erreur d'audit affichée, sans écart inventé", async () => {
    mocks.devices = () =>
      Promise.resolve([{ id: 'SW-1', name: 'SW-1', type: 'switch', ip: '10.1.1.1', cis_score: null, findings: null }])
    mocks.audit = () => Promise.reject({ response: { data: { detail: 'Configuration indisponible pour SW-1' } } })
    render(<NetDevOpsPage />)
    expect(await screen.findByTestId('netdevops-audit-error')).toHaveTextContent('Configuration indisponible pour SW-1')
    expect(screen.getAllByText('N/A').length).toBeGreaterThan(0)
    expect(screen.queryByText(/Plaintext password|SNMP v1 active|Default VLAN/)).toBeNull()
  })

  it("règle sans commande automatique : correction manuelle affichée, bouton d'application désactivé", async () => {
    mocks.devices = () =>
      Promise.resolve([{ id: 'SW-1', name: 'SW-1', type: 'switch', ip: '10.1.1.1', cis_score: 80, findings: 1 }])
    mocks.audit = () =>
      Promise.resolve({
        score: 80,
        config_source: 'live',
        violations: [
          { id: 'CIS-1.2', title: 'Enable secret', severity: 'HIGH', description: 'd', snippet: 'enable password x', remediation: 'Définir un enable secret de type 9', remediation_commands: '' },
        ],
      })
    render(<NetDevOpsPage />)
    expect(await screen.findByTestId('netdevops-manual-remediation')).toHaveTextContent('Définir un enable secret de type 9')
    await waitFor(() => expect(document.getElementById('netdevops-approve-btn')).toBeDisabled())
  })

  it('règle avec commandes : bouton activé et commandes exactes affichées', async () => {
    mocks.devices = () =>
      Promise.resolve([{ id: 'SW-1', name: 'SW-1', type: 'switch', ip: '10.1.1.1', cis_score: 90, findings: 1 }])
    mocks.audit = () =>
      Promise.resolve({
        score: 90,
        violations: [
          { id: 'CIS-1.6', title: 'HTTP actif', severity: 'MEDIUM', description: 'd', snippet: 'ip http server', remediation: 'x', remediation_commands: 'no ip http server' },
        ],
      })
    render(<NetDevOpsPage />)
    expect(await screen.findByText('no ip http server')).toBeInTheDocument()
    await waitFor(() => expect(document.getElementById('netdevops-approve-btn')).not.toBeDisabled())
  })
})
