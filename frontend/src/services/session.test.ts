import { beforeEach, describe, expect, it } from 'vitest'
import { clearPersonalData, clearSession, SESSION_KEYS } from './api'

describe('isolation des données entre comptes', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
  })

  it("efface jeton, profil, préférences d'interface et brouillons du compte précédent", () => {
    localStorage.setItem(SESSION_KEYS.token, 'jeton-alice')
    localStorage.setItem(SESSION_KEYS.user, '{"identifiant":"alice"}')
    localStorage.setItem(SESSION_KEYS.authUser, '{"identifiant":"alice"}')
    localStorage.setItem('sentinelle_sidebar_collapsed', 'true')
    sessionStorage.setItem('netdevops:prefill_code', 'no ip http server')
    clearPersonalData()
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('conserve uniquement la préférence de thème, liée au poste', () => {
    localStorage.setItem('sentinelle_theme_preference', 'night')
    localStorage.setItem(SESSION_KEYS.token, 'jeton')
    clearSession()
    expect(localStorage.getItem('sentinelle_theme_preference')).toBe('night')
    expect(localStorage.getItem(SESSION_KEYS.token)).toBeNull()
  })
})
