import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ me: vi.fn(), setup: vi.fn(), enable: vi.fn(), disable: vi.fn() }))
const auth = vi.hoisted(() => ({ changePassword: vi.fn() }))

vi.mock('../services/api', () => ({ mfaService: mocks, authService: auth }))

import { AccountSecurityModal } from './AccountSecurityModal'

describe('AccountSecurityModal', () => {
  beforeEach(() => {
    Object.values(mocks).forEach(m => m.mockReset())
    auth.changePassword.mockReset()
  })

  it("parcours complet d'activation : QR, confirmation, codes de secours", async () => {
    mocks.me.mockResolvedValue({ email: 'a@b.fr', mfa_active: false })
    mocks.setup.mockResolvedValue({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Sentinelle:a?secret=JBSWY3DPEHPK3PXP', issuer: 'Sentinelle' })
    mocks.enable.mockResolvedValue({ mfa_active: true, recovery_codes: ['aaaaaa-bbbb-cccccc', 'dddddd-eeee-ffffff'] })
    const user = userEvent.setup()
    render(<AccountSecurityModal onClose={vi.fn()} />)

    await user.click(await screen.findByRole('button', { name: /Activer l'authentification/ }))
    expect(await screen.findByTestId('mfa-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP')
    expect(document.querySelector('svg')).not.toBeNull() // QR code rendu

    const confirmer = screen.getByRole('button', { name: 'Confirmer' })
    expect(confirmer).toBeDisabled() // tant que le code n'a pas 6 chiffres
    await user.type(screen.getByLabelText('Code de confirmation'), '123456')
    await user.click(confirmer)

    expect(mocks.enable).toHaveBeenCalledWith('123456')
    const codes = await screen.findByTestId('recovery-codes')
    expect(codes).toHaveTextContent('aaaaaa-bbbb-cccccc')
    const terminer = screen.getByRole('button', { name: 'Terminer' })
    expect(terminer).toBeDisabled() // il faut cocher « j'ai conservé mes codes »
    await user.click(screen.getByRole('checkbox'))
    await user.click(terminer)
    expect(await screen.findByText(/activée\./)).toBeInTheDocument()
  })

  it('code de confirmation refusé : le message du serveur est affiché', async () => {
    mocks.me.mockResolvedValue({ email: 'a@b.fr', mfa_active: false })
    mocks.setup.mockResolvedValue({ secret: 'S', otpauth_uri: 'otpauth://totp/x?secret=S', issuer: 'x' })
    mocks.enable.mockRejectedValue(Object.assign(new Error('x'), { isAxiosError: true, response: { data: { detail: 'Code invalide.' } } }))
    const user = userEvent.setup()
    render(<AccountSecurityModal onClose={vi.fn()} />)
    await user.click(await screen.findByRole('button', { name: /Activer l'authentification/ }))
    await user.type(await screen.findByLabelText('Code de confirmation'), '000000')
    await user.click(screen.getByRole('button', { name: 'Confirmer' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Code invalide.')
  })

  it('MFA actif : désactivation avec mot de passe et code', async () => {
    mocks.me.mockResolvedValue({ email: 'a@b.fr', mfa_active: true })
    mocks.disable.mockResolvedValue({ mfa_active: false })
    const user = userEvent.setup()
    render(<AccountSecurityModal onClose={vi.fn()} />)
    const bouton = await screen.findByRole('button', { name: /Désactiver/ })
    expect(bouton).toBeDisabled()
    await user.type(screen.getByLabelText('Mot de passe actuel'), 'MotDePasse2026!')
    await user.type(screen.getByLabelText('Code MFA'), '123456')
    await user.click(bouton)
    await waitFor(() => expect(mocks.disable).toHaveBeenCalledWith('MotDePasse2026!', '123456'))
    expect(await screen.findByText(/désactivée/)).toBeInTheDocument()
  })

  it('changement de mot de passe : validations client puis appel serveur', async () => {
    mocks.me.mockResolvedValue({ email: 'a@b.fr', mfa_active: false })
    auth.changePassword.mockResolvedValue({ changed: true })
    const user = userEvent.setup()
    render(<AccountSecurityModal onClose={vi.fn()} />)

    const bouton = screen.getByRole('button', { name: 'Changer le mot de passe' })
    await user.type(screen.getByLabelText('Ancien mot de passe'), 'AncienMotDePasse2026')
    await user.type(screen.getByLabelText('Nouveau mot de passe'), 'court')
    expect(bouton).toBeDisabled()
    await user.clear(screen.getByLabelText('Nouveau mot de passe'))
    await user.type(screen.getByLabelText('Nouveau mot de passe'), 'NouveauMotDePasse2027')
    await user.type(screen.getByLabelText('Confirmer le nouveau mot de passe'), 'autre')
    expect(bouton).toBeDisabled()
    await user.clear(screen.getByLabelText('Confirmer le nouveau mot de passe'))
    await user.type(screen.getByLabelText('Confirmer le nouveau mot de passe'), 'NouveauMotDePasse2027')
    await user.click(bouton)
    expect(auth.changePassword).toHaveBeenCalledWith('AncienMotDePasse2026', 'NouveauMotDePasse2027')
    expect(await screen.findByText('Mot de passe modifié.')).toBeInTheDocument()
  })
})
