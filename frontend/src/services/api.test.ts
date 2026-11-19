import { AxiosError } from 'axios'
import { describe, expect, it, vi } from 'vitest'
import { apiClient, authService, isMfaRequiredError } from './api'

const erreur = (status: number, detail: string) =>
  new AxiosError('échec', String(status), undefined, undefined, {
    status,
    data: { detail },
    statusText: '',
    headers: {},
    config: {} as never,
  })

describe('isMfaRequiredError', () => {
  it('reconnaît la réponse 401 MFA_REQUIRED', () => {
    expect(isMfaRequiredError(erreur(401, 'MFA_REQUIRED'))).toBe(true)
  })
  it('ignore un mot de passe incorrect et les autres erreurs', () => {
    expect(isMfaRequiredError(erreur(401, 'Identifiants incorrects'))).toBe(false)
    expect(isMfaRequiredError(erreur(403, 'MFA_REQUIRED'))).toBe(false)
    expect(isMfaRequiredError(new Error('réseau'))).toBe(false)
  })
})

describe('authService.login', () => {
  it("n'envoie code_mfa que lorsqu'un code est fourni", async () => {
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { access_token: 't' } })
    await authService.login('alice', 'secret-1234')
    expect(post).toHaveBeenLastCalledWith('/auth/login', { identifiant: 'alice', mot_de_passe: 'secret-1234' })
    await authService.login('alice', 'secret-1234', '123456')
    expect(post).toHaveBeenLastCalledWith('/auth/login', {
      identifiant: 'alice',
      mot_de_passe: 'secret-1234',
      code_mfa: '123456',
    })
    post.mockRestore()
  })
})
