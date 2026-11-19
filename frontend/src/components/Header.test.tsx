import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemeProvider } from '../context/ThemeContext'

// Fonction simple (pas un espion vi.fn) : un espion rattache un .then au rejet, vu comme non géré.
const mocks = vi.hoisted(() => ({ impl: (() => Promise.resolve([])) as () => Promise<unknown> }))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return { ...actual, supervisionService: { ...actual.supervisionService, getAlerts: () => mocks.impl() } }
})

import { Header } from './Header'

const utilisateur = { identifiant: 'a', nom_complet: 'Alice Test', role: 'Administrateur' as const, email: 'a@b.fr' }
const afficher = () =>
  render(
    <ThemeProvider>
      <Header currentUser={utilisateur} />
    </ThemeProvider>,
  )

describe('Header : notifications réelles', () => {
  beforeEach(() => {
    mocks.impl = () => Promise.resolve([])
  })

  it('affiche les alertes actives renvoyées par le serveur (aucune alerte fictive)', async () => {
    const alertes = [
      { id: 1, severite: 'CRITICAL', titre: 'Disque saturé', message: 'Remplissage 97 %', equipement_nom: 'SRV-X', module_origine: 'Supervision', statut: 'Active', date_creation: new Date().toISOString() },
    ]
    mocks.impl = () => Promise.resolve(alertes)
    afficher()
    await userEvent.setup().click(document.getElementById('header-notifications-btn')!)
    expect(await screen.findByText('Disque saturé')).toBeInTheDocument()
    expect(screen.queryByText(/Switch-Core-01|Datacenter B|Firewall-Edge/)).toBeNull()
  })

  it("sans alerte : message explicite", async () => {
    mocks.impl = () => Promise.resolve([])
    afficher()
    await userEvent.setup().click(document.getElementById('header-notifications-btn')!)
    expect(await screen.findByText('Aucune alerte active.')).toBeInTheDocument()
  })

  it('signale clairement un serveur injoignable', async () => {
    mocks.impl = () => Promise.reject(new Error('réseau'))
    afficher()
    await userEvent.setup().click(document.getElementById('header-notifications-btn')!)
    expect(await screen.findByText(/Alertes indisponibles/)).toBeInTheDocument()
  })
})
