import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  send: (() => Promise.reject(new Error('réseau'))) as () => Promise<unknown>,
}))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return { ...actual, assistantService: { ...actual.assistantService, sendMessage: () => mocks.send() } }
})

import { AssistantPage } from './AssistantPage'

describe('AssistantPage : aucune réponse inventée', () => {
  beforeEach(() => {
    // jsdom n'implémente pas scrollIntoView
    Element.prototype.scrollIntoView = () => {}
    mocks.send = () => Promise.reject(new Error('réseau'))
  })

  it("serveur injoignable : message d'erreur explicite, pas de tableau ni d'analyse fictifs", async () => {
    render(<AssistantPage currentUser={null} />)
    const champ = screen.getByRole('textbox')
    await userEvent.setup().type(champ, 'Quels serveurs risquent une saturation disque ?{enter}')
    expect(await screen.findByText(/n'a pas pu répondre/)).toBeInTheDocument()
    expect(screen.queryByText(/APP-SRV-01|DB-CLUSTER-M1|STO-NODE-04|DIST-SW-A/)).toBeNull()
    expect(screen.queryByText('Proposer nettoyage')).toBeNull()
  })

  it('affiche la réponse du serveur telle quelle', async () => {
    mocks.send = () => Promise.resolve({ response: 'Réponse du serveur', sources: ['Parc'], mode: 'rag_local' })
    render(<AssistantPage currentUser={null} />)
    await userEvent.setup().type(screen.getByRole('textbox'), 'bonjour{enter}')
    expect(await screen.findByText('Réponse du serveur')).toBeInTheDocument()
  })
})
