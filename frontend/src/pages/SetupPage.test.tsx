import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemeProvider } from '../context/ThemeContext'

const mocks = vi.hoisted(() => ({ setup: vi.fn() }))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return { ...actual, authService: { ...actual.authService, setup: mocks.setup } }
})

import { SetupPage } from './SetupPage'

const afficher = () => {
  const onSetupSuccess = vi.fn()
  render(
    <ThemeProvider>
      <SetupPage onSetupSuccess={onSetupSuccess} />
    </ThemeProvider>,
  )
  return onSetupSuccess
}

describe('SetupPage', () => {
  beforeEach(() => mocks.setup.mockReset())

  it("propose d'abord le choix du profil du poste, Administrateur par défaut", async () => {
    afficher()
    expect(screen.getByTestId('setup-choix-profil')).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /Administrateur/ })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('radio', { name: /Technicien/ })).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('radio', { name: /Visiteur/ })).toBeInTheDocument()
    expect(screen.queryByLabelText('Identifiant')).toBeNull()
  })

  it('transmet le profil choisi au serveur', async () => {
    mocks.setup.mockResolvedValue({ access_token: 'jeton', identifiant: 'tech1', nom_complet: 'Tech Un', role: 'Technicien' })
    const onSetupSuccess = afficher()
    const user = userEvent.setup()
    await user.click(screen.getByRole('radio', { name: /Technicien/ }))
    expect(screen.getByText(/Aucun administrateur n'existera/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Continuer' }))
    await user.type(screen.getByLabelText('Identifiant'), 'tech1')
    await user.type(screen.getByLabelText('Nom complet'), 'Tech Un')
    await user.type(screen.getByLabelText('Email'), 'tech1@exemple.fr')
    await user.type(screen.getByLabelText('Mot de passe'), 'MotDePasse2026!')
    await user.type(screen.getByLabelText('Confirmer le mot de passe'), 'MotDePasse2026!')
    await user.click(screen.getByRole('button', { name: 'Créer le compte' }))
    await waitFor(() => expect(onSetupSuccess).toHaveBeenCalled())
    expect(mocks.setup).toHaveBeenCalledWith(expect.objectContaining({ role: 'Technicien' }))
    expect(onSetupSuccess.mock.calls[0][0]).toMatchObject({ role: 'Technicien' })
  })

  it('refuse un mot de passe faible ou non confirmé (bouton inactif)', async () => {
    afficher()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Continuer' }))
    await user.type(screen.getByLabelText('Identifiant'), 'root')
    await user.type(screen.getByLabelText('Nom complet'), 'Root Admin')
    await user.type(screen.getByLabelText('Email'), 'root@exemple.fr')
    await user.type(screen.getByLabelText('Mot de passe'), 'court1')
    expect(screen.getByRole('button', { name: 'Créer le compte' })).toBeDisabled()
    expect(screen.getByTestId('setup-erreurs')).toHaveTextContent('12 caractères minimum')
  })

  it('crée le premier administrateur avec des saisies valides', async () => {
    mocks.setup.mockResolvedValue({ access_token: 'jeton', identifiant: 'root', nom_complet: 'Root Admin', role: 'Administrateur' })
    const onSetupSuccess = afficher()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Continuer' }))
    await user.type(screen.getByLabelText('Identifiant'), 'root')
    await user.type(screen.getByLabelText('Nom complet'), 'Root Admin')
    await user.type(screen.getByLabelText('Email'), 'root@exemple.fr')
    await user.type(screen.getByLabelText('Mot de passe'), 'MotDePasse2026!')
    await user.type(screen.getByLabelText('Confirmer le mot de passe'), 'MotDePasse2026!')
    await user.click(screen.getByRole('button', { name: 'Créer le compte' }))
    await waitFor(() => expect(onSetupSuccess).toHaveBeenCalled())
    expect(mocks.setup).toHaveBeenCalledWith({
      identifiant: 'root', email: 'root@exemple.fr', nom_complet: 'Root Admin', mot_de_passe: 'MotDePasse2026!', role: 'Administrateur',
    })
    expect(onSetupSuccess.mock.calls[0][0]).toMatchObject({ role: 'Administrateur', identifiant: 'root' })
  })
})
