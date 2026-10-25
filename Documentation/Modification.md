# Modifications de la Stack Technique — Cahier des Charges Sentinelle AIOps

Ce document répertorie de manière exhaustive, section par section et page par page (en référence au document PDF original de 26 pages `Cahier_des_Charges_Sentinelle AIOps.pdf`), l'ensemble des ajustements à reporter pour aligner le cahier des charges avec les choix techniques validés :

* **Backend :** **FastAPI** + **SQLite par défaut (via SQLAlchemy)**, avec compatibilité immédiate PostgreSQL.
* **Frontend :** **React (Vite + TypeScript + Tailwind CSS)** pour une reproduction pixel-perfect des maquettes Stitch.
* **IA & Automatisation :** **Scikit-learn** (Isolation Forest), Régression (Time-To-Failure), **Netmiko** (Cisco IOS), **Ollama** (LLM local).

---

## 1. Page de Garde / Couverture (Page 1)

* **Zone concernée :** Mention des technologies sous le cadre pédagogique.
* **Ancien texte :**
  > `Technologies : Python · Machine Learning · NetDevOps · Streamlit`
* **Nouveau texte à appliquer :**
  > `Technologies : Python (FastAPI) · React (Vite / Tailwind CSS) · SQLite / PostgreSQL · NetDevOps · Machine Learning`

---

## 2. Section 1.2 — Travail de maturation réalisé (Page 3/25 — page 4 du PDF)

* **Zone concernée :** Liste à puces des « Axes de maturation ajoutés ».
* **Puce « Architecture découplée API REST » :**
  * *Ancien :*
    > `Architecture découplée API REST : séparation backend (FastAPI) / frontend (Streamlit ou React) pour permettre une évolution vers une application mobile ou une intégration tierce.`
  * *Nouveau :*
    > `Architecture découplée API REST : séparation stricte backend API REST (FastAPI) / frontend SPA (React + Vite + Tailwind CSS) pour garantir une réactivité optimale, une reproduction fidèle des maquettes et une évolutivité vers de futurs clients.`
* **Puce « Base de données relationnelle structurée » :**
  * *Ancien :*
    > `Base de données relationnelle structurée (PostgreSQL) avec modèle de données formalisé, remplaçant le simple stockage fichier envisagé initialement.`
  * *Nouveau :*
    > `Base de données relationnelle structurée (SQLite en environnement local / démonstration pour une portabilité totale sans dépendance de serveur SGBD tiers, avec compatibilité PostgreSQL via l'ORM SQLAlchemy).`

---

## 3. Section 3.1 — Périmètre fonctionnel : Ce qui est inclus (Page 6/25 — page 7 du PDF)

* **Zone concernée :** Tableau du périmètre fonctionnel, ligne « Reporting / Admin ».
* **Ancien contenu :**
  | Domaine | Inclus dans la version de soutenance |
  | :--- | :--- |
  | **Reporting / Admin** | Dashboard Streamlit, rapports PDF, gestion des rôles, notifications |
* **Nouveau contenu à appliquer :**
  | Domaine | Inclus dans la version de soutenance |
  | :--- | :--- |
  | **Reporting / Admin** | Dashboard React (Vite + Tailwind CSS), rapports PDF, gestion des rôles, notifications |

---

## 4. Section 4 — Architecture globale de la solution (Page 7/25 — page 8 du PDF)

### 4.1 Vue d'ensemble (Paragraphe 1)
* **Ancien :**
  > `Un backend API REST (FastAPI) expose les données et les actions aux interfaces (dashboard Streamlit, assistant IA, futurs clients).`
* **Nouveau :**
  > `Un backend API REST (FastAPI) expose les données et les actions aux interfaces (dashboard web React, assistant IA conversationnel, futurs clients).`

### 4.2 Schéma logique (Tableau des couches)
* **Ligne « Persistance » :**
  * *Ancien :* `PostgreSQL (ou SQLite en mode démo), fichiers de sauvegarde de configuration`
  * *Nouveau :* `SQLite par défaut (zéro dépendance de service pour la soutenance), compatible PostgreSQL via SQLAlchemy, sauvegardes de configuration`
* **Ligne « Présentation » :**
  * *Ancien :* `Dashboard Streamlit, chatbot IA, rapports PDF, notifications`
  * *Nouveau :* `Dashboard Single Page Application React (Vite + Tailwind CSS), chatbot IA intégré, rapports PDF, notifications`

---

## 5. Section 4.3 — Schéma technique simplifié (Page 8/25 — page 9 du PDF)

* **Zone concernée :** Bloc visuel en bas à gauche du diagramme de flux.
* **Ancien libellé :**
  > `Dashboard Streamlit (Plotly)`
* **Nouveau libellé :**
  > `Dashboard React + Vite (Tailwind CSS / Recharts / Plotly)`

---

## 6. Section 5.5 — Module Reporting & Administration (Page 12/25 — page 13 du PDF)

* **Zone 1 : Fonctionnement détaillé (1er point de liste)**
  * *Ancien :*
    > `• Tableau de bord Streamlit présentant les indicateurs globaux (état du parc, alertes en cours, prédictions à venir, score de conformité moyen) avec graphiques Plotly interactifs.`
  * *Nouveau :*
    > `• Tableau de bord React (Vite + Tailwind CSS) présentant les indicateurs globaux (état du parc, alertes en cours, prédictions à venir, score de conformité moyen) avec visualisations interactives (Recharts / Plotly).`
* **Zone 2 : Sous-section « Technologies retenues »**
  * *Ancien :*
    > `Technologies retenues : Streamlit, Plotly, ReportLab/WeasyPrint (génération PDF), smtplib, API Telegram Bot, Webhook Discord.`
  * *Nouveau :*
    > `Technologies retenues : React 18/19, Vite, Tailwind CSS, Recharts / Plotly, ReportLab (génération PDF via FastAPI), smtplib, API Telegram Bot, Webhook Discord.`

---

## 7. Section 5.6 — Module Assistant IA conversationnel (Page 13/25 — page 14 du PDF)

* **Zone 1 : Fonctionnement détaillé (1er point de liste)**
  * *Ancien :*
    > `• Interface de chat intégrée au dashboard, connectée au même LLM local que le module NetDevOps.`
  * *Nouveau :*
    > `• Interface de chat interactive intégrée à la SPA React (composant drawer / modal dédié), connectée via FastAPI au LLM local.`
* **Zone 2 : Sous-section « Technologies retenues »**
  * *Ancien :*
    > `Technologies retenues : Ollama (LLM local), function calling structuré, FastAPI, Streamlit chat component.`
  * *Nouveau :*
    > `Technologies retenues : Ollama (LLM local), function calling structuré, FastAPI, composant de messagerie instantanée React.`

---

## 8. Section 6 — Modèle de données (Page 14/25 — page 15 du PDF)

* **Zone concernée :** Paragraphe d'introduction sous le titre.
* **Ancien :**
  > `La base de données centrale (PostgreSQL en production de démonstration, SQLite acceptable pour un mode allégé) structure l'ensemble des informations collectées et produites par les modules.`
* **Nouveau :**
  > `La base de données centrale (SQLite en environnement local / démonstration pour une portabilité immédiate sans dépendance de serveur SGBD tiers, compatible PostgreSQL sans modification applicative via SQLAlchemy) structure l'ensemble des informations collectées et produites par les modules.`

---

## 9. Section 8.1 — Composants technologiques (Page 16/25 — page 17 du PDF)

Mettre à jour les lignes suivantes du tableau récapitulatif de la stack :

| Composant | Choix technologique | Justification actualisée |
| :--- | :--- | :--- |
| **Langages principaux** | **Python 3.11+ & TypeScript / JavaScript** | Python pour l'écosystème IA/réseau/FastAPI. TypeScript/React pour la solidité et la modularité du frontend. |
| **Backend / API** | **FastAPI** | Performances asynchrones, typage strict Pydantic, auto-génération de la documentation interactive Swagger/OpenAPI (`/docs`). |
| **Frontend / Dashboard** | **React 18/19 (Vite + Tailwind CSS)** | Restitution pixel-perfect des maquettes Stitch validées, ergonomie professionnelle « poste de commandement », fluidité SPA sans rechargement de page. |
| **Base de données** | **SQLite par défaut (compatible PostgreSQL via SQLAlchemy)** | Zéro friction d'installation, résilience maximale pour le jour de la soutenance (fichier local autonome), évolutivité immédiate vers PostgreSQL sans modifier le code. |

---

## 10. Section 8.2 — Charte graphique de l'interface (Page 17/25 — page 18 du PDF)

* **Zone concernée :** Paragraphe d'introduction de la charte graphique.
* **Ancien :**
  > `...Elle fait foi pour toute implémentation ultérieure de l'interface (feuille de style, composants Streamlit/React).`
* **Nouveau :**
  > `...Elle fait foi pour toute implémentation de l'interface (configuration Tailwind CSS et composants modulaires React).`

---

## 11. Section 11.2 — Planning prévisionnel (Page 21/25 — page 22 du PDF)

* **Zone concernée :** Ligne de la Phase 2.
* **Ancien :**
  | Phase | Durée | Contenu |
  | :--- | :--- | :--- |
  | **Phase 2 — Socle technique** | 3 semaines | Base de données, API FastAPI, authentification/RBAC, squelette du dashboard |
* **Nouveau :**
  | Phase | Durée | Contenu |
  | :--- | :--- | :--- |
  | **Phase 2 — Socle technique** | 3 semaines | Base de données SQLite/SQLAlchemy, API FastAPI, authentification/RBAC, squelette frontend React + Vite + Tailwind |

---

## 12. Section 11.3 — Budget prévisionnel (Page 21/25 — page 22 du PDF)

* **Zone concernée :** Tableau du budget, ligne « Licences logicielles ».
* **Ancien :**
  > `Python, PostgreSQL, Streamlit, Ollama, Docker : composants open-source (0 €)`
* **Nouveau :**
  > `Python, SQLite/PostgreSQL, React, Vite, Tailwind CSS, Ollama, Docker : composants 100 % open-source et gratuits (0 €)`
