import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemeProvider } from '../context/ThemeContext'

const mocks = vi.hoisted(() => ({ forgotPassword: vi.fn(), resetPassword: vi.fn(), register: vi.fn() }))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return {
    ...actual,
    authService: {
      ...actual.authService,
      forgotPassword: mocks.forgotPassword,
      resetPassword: mocks.resetPassword,
      register: mocks.register,
    },
  }
})

import { ForgotPasswordPage } from './ForgotPasswordPage'
import { ResetPasswordPage } from './ResetPasswordPage'
import { RegisterPage } from './RegisterPage'

const enveloppe = (ui: React.ReactElement) => render(<ThemeProvider>{ui}</ThemeProvider>)

describe('Mot de passe oublié', () => {
  beforeEach(() => {
    mocks.forgotPassword.mockReset()
    mocks.resetPassword.mockReset()
  })

  it("sans e-mail configuré, annonce honnêtement qu'il faut demander un code à l'administrateur", async () => {
    mocks.forgotPassword.mockResolvedValue({ mode: 'admin_code', message: "L'envoi d'e-mails n'est pas configuré. Demandez un code à votre administrateur." })
    enveloppe(<ForgotPasswordPage onBackToLogin={vi.fn()} onHaveCode={vi.fn()} />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/Identifiant ou e-mail/), 'alice')
    await user.click(screen.getByRole('button', { name: 'Continuer' }))
    expect(await screen.findByTestId('oubli-reponse')).toHaveTextContent("n'est pas configuré")
    expect(screen.getByRole('button', { name: /code de mon administrateur/ })).toBeInTheDocument()
    expect(mocks.forgotPassword).toHaveBeenCalledWith('alice')
  })

  it('avec e-mail : message neutre puis accès à la saisie du code', async () => {
    mocks.forgotPassword.mockResolvedValue({ mode: 'email', message: "Si ce compte existe, un e-mail vient d'être envoyé." })
    const onHaveCode = vi.fn()
    enveloppe(<ForgotPasswordPage onBackToLogin={vi.fn()} onHaveCode={onHaveCode} />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/Identifiant ou e-mail/), 'alice@exemple.fr')
    await user.click(screen.getByRole('button', { name: 'Continuer' }))
    await user.click(await screen.findByRole('button', { name: /reçu un lien ou un code/ }))
    expect(onHaveCode).toHaveBeenCalled()
  })

  it('la réinitialisation exige un mot de passe valide et confirmé', async () => {
    enveloppe(<ResetPasswordPage onDone={vi.fn()} onBackToLogin={vi.fn()} />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Identifiant'), 'alice')
    await user.type(screen.getByLabelText('Code de réinitialisation'), 'ABCDE-FGHJK')
    await user.type(screen.getByLabelText('Nouveau mot de passe'), 'court1')
    expect(screen.getByRole('button', { name: 'Changer le mot de passe' })).toBeDisabled()
    expect(screen.getByTestId('reset-erreurs')).toHaveTextContent('12 caractères minimum')
  })

  it('préremplit identifiant et code depuis le lien et enregistre le nouveau mot de passe', async () => {
    mocks.resetPassword.mockResolvedValue({ reset: true })
    enveloppe(<ResetPasswordPage identifiantInitial="alice" codeInitial="jeton-du-lien" onDone={vi.fn()} onBackToLogin={vi.fn()} />)
    const user = userEvent.setup()
    expect(screen.getByLabelText('Identifiant')).toHaveValue('alice')
    await user.type(screen.getByLabelText('Nouveau mot de passe'), 'NouveauMdp2026!')
    await user.type(screen.getByLabelText('Confirmer le mot de passe'), 'NouveauMdp2026!')
    await user.click(screen.getByRole('button', { name: 'Changer le mot de passe' }))
    expect(await screen.findByTestId('reset-reussi')).toBeInTheDocument()
    expect(mocks.resetPassword).toHaveBeenCalledWith('alice', 'jeton-du-lien', 'NouveauMdp2026!')
  })

  it("affiche l'erreur du serveur pour un code invalide", async () => {
    const { AxiosError } = await import('axios')
    mocks.resetPassword.mockRejectedValue(new AxiosError('400', '400', undefined, undefined, {
      status: 400, data: { detail: 'Code invalide ou expiré.' }, statusText: '', headers: {}, config: {} as never,
    }))
    enveloppe(<ResetPasswordPage identifiantInitial="alice" codeInitial="mauvais" onDone={vi.fn()} onBackToLogin={vi.fn()} />)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Nouveau mot de passe'), 'NouveauMdp2026!')
    await user.type(screen.getByLabelText('Confirmer le mot de passe'), 'NouveauMdp2026!')
    await user.click(screen.getByRole('button', { name: 'Changer le mot de passe' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Code invalide ou expiré.')
  })
})

describe('Création de compte avec choix du profil (poste local)', () => {
  beforeEach(() => mocks.register.mockReset())

  it('propose le choix du profil et le transmet', async () => {
    mocks.register.mockResolvedValue({ access_token: 'j', identifiant: 'bob', nom_complet: 'Bob', role: 'Technicien', email: 'bob@exemple.fr' })
    enveloppe(<RegisterPage onRegisterSuccess={vi.fn()} onSwitchToLogin={vi.fn()} rolesDisponibles={['Administrateur', 'Technicien', 'Visiteur']} />)
    const user = userEvent.setup()
    expect(screen.getByRole('radiogroup', { name: 'Profil du compte' })).toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: /Technicien/ }))
    await user.type(document.getElementById('register-identifiant-input')!, 'bob')
    await user.type(document.getElementById('register-nom-complet-input')!, 'Bob')
    await user.type(document.getElementById('register-email-input')!, 'bob@exemple.fr')
    await user.type(document.getElementById('register-password-input')!, 'MotDePasse2026!')
    await user.type(document.getElementById('register-confirm-password-input')!, 'MotDePasse2026!')
    await user.click(document.getElementById('register-submit-btn')!)
    await waitFor(() => expect(mocks.register).toHaveBeenCalled())
    expect(mocks.register).toHaveBeenCalledWith(expect.objectContaining({ role: 'Technicien' }))
  })

  it("depuis le réseau (un seul profil), aucun choix et aucun rôle envoyé", () => {
    enveloppe(<RegisterPage onRegisterSuccess={vi.fn()} onSwitchToLogin={vi.fn()} />)
    expect(screen.queryByRole('radiogroup')).toBeNull()
    expect(screen.getByText(/Visiteur \(lecture seule\)/)).toBeInTheDocument()
  })
})
