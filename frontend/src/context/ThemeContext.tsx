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

const NIGHT_START_HOUR = 19; // 19:00 (7 PM)
const NIGHT_END_HOUR = 7;   // 07:00 (7 AM)

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [preference, setPreferenceState] = useState<ThemePreference>(() => {
    try {
      const stored = localStorage.getItem('sentinelle_theme_preference');
      if (stored === 'night' || stored === 'day' || stored === 'auto') {
        return stored;
      }
    } catch {
      /* ignore */
    }
    return 'auto';
  });

  const [currentHour, setCurrentHour] = useState<number>(() => new Date().getHours());

  // Mise à jour de l'heure toutes les minutes pour recalculer le mode temporel
  useEffect(() => {
    const updateTime = () => setCurrentHour(new Date().getHours());
    const interval = setInterval(updateTime, 60000);
    return () => clearInterval(interval);
  }, []);

  // Détection de la tranche horaire nocturne (19h00 -> 07h00)
  const isNightTime = currentHour >= NIGHT_START_HOUR || currentHour < NIGHT_END_HOUR;

  // Détermination du thème actif effectif
  const activeTheme: ActiveTheme =
    preference === 'auto'
      ? isNightTime
        ? 'night'
        : 'day'
      : preference;

  // Application de la classe sur l'élément racine <html> et <body>
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
      localStorage.setItem('sentinelle_theme_preference', pref);
    } catch {
      /* ignore */
    }
  };

  // Cycle entre auto -> night -> day -> auto
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
