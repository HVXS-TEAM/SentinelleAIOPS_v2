import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ThemeProvider } from '../context/ThemeContext'
import { RegisterPage } from './RegisterPage'

describe('RegisterPage', () => {
  const afficher = () =>
    render(
      <ThemeProvider>
        <RegisterPage onRegisterSuccess={vi.fn()} onSwitchToLogin={vi.fn()} />
      </ThemeProvider>,
    )

  it("ne propose plus de choix de rôle : l'inscription crée un Visiteur", () => {
    afficher()
    expect(screen.getByText(/Visiteur \(lecture seule\)/)).toBeInTheDocument()
    expect(screen.queryByRole('combobox')).toBeNull()
    expect(screen.queryByText(/Technicien$/)).toBeNull()
  })

  it('annonce un mot de passe de 12 caractères minimum', () => {
    afficher()
    expect(screen.getByPlaceholderText('Min. 12 caractères, lettres et chiffres')).toBeInTheDocument()
  })
})
