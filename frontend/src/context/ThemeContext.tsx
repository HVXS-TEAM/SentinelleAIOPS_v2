import React, { createContext, useContext, useState, useEffect } from 'react';

export type ThemePreference = 'auto' | 'night' | 'day';
export type ActiveTheme = 'night' | 'day';

interface ThemeContextType {
  preference: ThemePreference;
  activeTheme: ActiveTheme;
  isNightTime: boolean;
  currentHour: number;
  setPreference: (pref: ThemePreference) => void;
  cycleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

const NIGHT_START_HOUR = 19; // 19:00 (7 PM) -> Bascule automatique en Mode Nocturne (Laser SOC)
const NIGHT_END_HOUR = 7;    // 07:00 (7 AM) -> Bascule automatique en Mode Jour (Haute Lisibilité)

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Par défaut au lancement de la session, le thème suit automatiquement l'heure système ('auto')
  const [preference, setPreferenceState] = useState<ThemePreference>(() => {
    try {
      const sessionPref = sessionStorage.getItem('sentinelle_theme_preference');
      if (sessionPref === 'night' || sessionPref === 'day' || sessionPref === 'auto') {
        return sessionPref;
      }
      // Réinitialise l'ancien localStorage bloqué pour garantir la bascule horaire automatique
      localStorage.setItem('sentinelle_theme_preference', 'auto');
    } catch {
      /* ignore */
    }
    return 'auto';
  });

  const [currentHour, setCurrentHour] = useState<number>(() => new Date().getHours());

  // Vérification horaire toutes les 15 secondes pour basculer automatiquement à 07h00 et 19h00
  useEffect(() => {
    const updateTime = () => setCurrentHour(new Date().getHours());
    updateTime();
    const interval = setInterval(updateTime, 15000);
    return () => clearInterval(interval);
  }, []);

  // Détection de la tranche horaire nocturne (19h00 -> 07h00)
  const isNightTime = currentHour >= NIGHT_START_HOUR || currentHour < NIGHT_END_HOUR;

  // Détermination du thème actif effectif selon l'heure ou le choix manuel
  const activeTheme: ActiveTheme =
    preference === 'auto'
      ? isNightTime
        ? 'night'
        : 'day'
      : preference;

  // Application de la classe sur l'élément racine <html>
  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('theme-night', 'theme-day', 'dark', 'light');

    if (activeTheme === 'night') {
      root.classList.add('theme-night', 'dark');
      root.style.colorScheme = 'dark';
    } else {
      root.classList.add('theme-day', 'light');
      root.style.colorScheme = 'light';
    }
  }, [activeTheme]);

  const setPreference = (pref: ThemePreference) => {
    setPreferenceState(pref);
    try {
      sessionStorage.setItem('sentinelle_theme_preference', pref);
      localStorage.setItem('sentinelle_theme_preference', pref);
    } catch {
      /* ignore */
    }
  };

  // Cycle entre auto (selon l'heure) -> night -> day -> auto
  const cycleTheme = () => {
    if (preference === 'auto') {
      setPreference('night');
    } else if (preference === 'night') {
      setPreference('day');
    } else {
      setPreference('auto');
    }
  };

  return (
    <ThemeContext.Provider
      value={{
        preference,
        activeTheme,
        isNightTime,
        currentHour,
        setPreference,
        cycleTheme,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
