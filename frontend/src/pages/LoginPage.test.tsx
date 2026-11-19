import { AxiosError } from 'axios'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ThemeProvider } from '../context/ThemeContext'

const mocks = vi.hoisted(() => ({ login: vi.fn(), me: vi.fn() }))

vi.mock('../services/api', async importOriginal => {
  const actual = await importOriginal<typeof import('../services/api')>()
  return {
    ...actual,
    authService: { ...actual.authService, login: mocks.login },
    mfaService: { ...actual.mfaService, me: mocks.me },
  }
})

import { LoginPage } from './LoginPage'

const reponse = { access_token: 'jeton', identifiant: 'alice', nom_complet: 'Alice', role: 'Technicien' }
const mfaRequis = () =>
  new AxiosError('401', '401', undefined, undefined, {
    status: 401,
    data: { detail: 'MFA_REQUIRED' },
    statusText: '',
    headers: {},
    config: {} as never,
  })

const afficher = () => {
  const onLoginSuccess = vi.fn()
  render(
    <ThemeProvider>
      <LoginPage onLoginSuccess={onLoginSuccess} />
    </ThemeProvider>,
  )
  return onLoginSuccess
}

const saisir = async (user: ReturnType<typeof userEvent.setup>, id: string, valeur: string) => {
  const champ = document.getElementById(id) as HTMLInputElement
  await user.clear(champ)
  await user.type(champ, valeur)
}

describe('LoginPage', () => {
  beforeEach(() => {
    mocks.login.mockReset()
    mocks.me.mockReset().mockResolvedValue({ email: 'alice@exemple.fr', mfa_active: false })
  })

  it("n'affiche pas le champ MFA tant que le serveur ne l'exige pas", () => {
    afficher()
    expect(document.getElementById('login-mfa-input')).toBeNull()
  })

  it('connexion simple : pas de code envoyé, e-mail réel issu du serveur', async () => {
    mocks.login.mockResolvedValue(reponse)
    const onLoginSuccess = afficher()
    const user = userEvent.setup()
    await saisir(user, 'login-username-input', 'alice')
    await saisir(user, 'login-password-input', 'MotDePasse2026!')
    await user.click(document.getElementById('login-submit-btn')!)
    await waitFor(() => expect(onLoginSuccess).toHaveBeenCalled())
    expect(mocks.login).toHaveBeenCalledWith('alice', 'MotDePasse2026!', undefined)
    expect(onLoginSuccess.mock.calls[0][0]).toMatchObject({ identifiant: 'alice', email: 'alice@exemple.fr' })
  })

  it('compte avec MFA : demande le code puis le transmet au serveur', async () => {
    mocks.login.mockRejectedValueOnce(mfaRequis()).mockResolvedValueOnce(reponse)
    const onLoginSuccess = afficher()
    const user = userEvent.setup()
    await saisir(user, 'login-username-input', 'alice')
    await saisir(user, 'login-password-input', 'MotDePasse2026!')
    await user.click(document.getElementById('login-submit-btn')!)

    const champMfa = await waitFor(() => {
      const el = document.getElementById('login-mfa-input')
      expect(el).not.toBeNull()
      return el as HTMLInputElement
    })
    expect(onLoginSuccess).not.toHaveBeenCalled()

    await user.click(document.getElementById('login-submit-btn')!) // sans code : refusé côté client
    expect(mocks.login).toHaveBeenCalledTimes(1)

    await user.type(champMfa, '654321')
    await user.click(document.getElementById('login-submit-btn')!)
    await waitFor(() => expect(onLoginSuccess).toHaveBeenCalled())
    expect(mocks.login).toHaveBeenLastCalledWith('alice', 'MotDePasse2026!', '654321')
  })

  it("aucun compte ni mot de passe n'est pré-rempli, aucun profil de démonstration", () => {
    afficher()
    expect((document.getElementById('login-username-input') as HTMLInputElement).value).toBe('')
    expect((document.getElementById('login-password-input') as HTMLInputElement).value).toBe('')
    expect(document.body.textContent).not.toMatch(/DÉMONSTRATION|Password2026/i)
  })

  it("le lien « Mot de passe oublié ? » n'apparaît que si la page est branchée dessus", async () => {
    const onForgot = vi.fn()
    render(
      <ThemeProvider>
        <LoginPage onLoginSuccess={vi.fn()} onForgotPassword={onForgot} />
      </ThemeProvider>,
    )
    await userEvent.setup().click(screen.getByRole('button', { name: 'Mot de passe oublié ?' }))
    expect(onForgot).toHaveBeenCalled()
    expect(document.getElementById('login-forgot-password-btn')).not.toBeNull()
  })

  it("sans inscription ouverte, le lien « Créer un nouveau compte » est absent", () => {
    afficher()
    expect(document.getElementById('login-switch-to-register-btn')).toBeNull()
  })
})
