import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  stats: (() => Promise.resolve(null)) as () => Promise<unknown>,
  events: (() => Promise.resolve([])) as () => Promise<unknown>,
  block: (() => Promise.resolve({})) as (...a: unknown[]) => Promise<unknown>,
  blockArgs: [] as unknown[],
}))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return {
    ...actual,
    securiteService: {
      ...actual.securiteService,
      getStats: () => mocks.stats(),
      getEvents: () => mocks.events(),
      blockIp: (...a: unknown[]) => {
        mocks.blockArgs = a
        return mocks.block(...a)
      },
    },
    parcService: { ...actual.parcService, getEquipements: () => Promise.resolve([]) },
  }
})

import { SecuritePage } from './SecuritePage'

const stats = {
  total_evenements: 42, total_anomalies: 3, attaques_critiques: 1, ips_bloquees: 2,
  modele_actif: 'regles_statiques', echantillons_baseline: 4, echantillons_requis: 30,
  evenements_par_source: { journald: 42 }, derniere_observation: '2026-11-18T06:59:01',
  syslog_actif: false, syslog_datagrammes_recus: 0, syslog_ignores_source_inconnue: 0,
}
const evenement = {
  id: 9, equipement_id: null, source_ip: '203.0.113.7', source_ip_anonymisee: '203.0.113.***',
  utilisateur_cible: 'root', type_evenement: 'brute_force', score_anomalie: 0, severite: 'CRITICAL',
  is_anomaly: true, explication: '8 échecs', tentatives_minute: 8, horodatage: '2026-11-18T06:59:01',
}

describe('SecuritePage : données réelles uniquement', () => {
  beforeEach(() => {
    mocks.stats = () => Promise.resolve(stats)
    mocks.events = () => Promise.resolve([])
    mocks.block = () => Promise.resolve({ message: 'ok', firewall_mode: 'IPTABLES' })
  })

  it('affiche les compteurs et le moteur renvoyés par le serveur, sans pourcentage figé', async () => {
    render(<SecuritePage />)
    expect((await screen.findAllByText('42')).length).toBeGreaterThanOrEqual(2)
    const panneau = screen.getByTestId('securite-engine-panel')
    expect(panneau).toHaveTextContent('Règles statiques')
    expect(panneau).toHaveTextContent('4 / 30')
    expect(panneau).toHaveTextContent('journald')
    expect(screen.queryByText(/85%|95%|72%|RGPD & CIS READY/)).toBeNull()
  })

  it('statistiques indisponibles : message explicite', async () => {
    mocks.stats = () => Promise.reject(new Error('réseau'))
    render(<SecuritePage />)
    expect(await screen.findByTestId('securite-stats-unavailable')).toBeInTheDocument()
  })

  it("blocage refusé par le serveur : le motif exact est affiché, l'incident reste non bloqué", async () => {
    mocks.events = () => Promise.resolve([evenement])
    mocks.block = () => Promise.reject({ response: { data: { detail: 'Aucune règle de pare-feu créée : droits administrateur requis' } } })
    render(<SecuritePage />)
    await userEvent.setup().click(await screen.findByText('brute_force'))
    await userEvent.setup().click(await screen.findByText(/Bloquer l'IP Source/))
    expect(await screen.findByText(/droits administrateur requis/)).toBeInTheDocument()
    expect(mocks.blockArgs[0]).toBe('203.0.113.7')
    expect(mocks.blockArgs[1]).toBe(9)
    await waitFor(() => expect(screen.getByText(/Bloquer l'IP Source/)).toBeInTheDocument())
  })
})
