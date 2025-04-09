Wi-Fi Hacking Tool
====================

Hello Gen Z friends (and everyone else)! Bienvenue sur ce projet Wi-Fi Hacking Tool.
Ce script, développé en Python avec une interface Tkinter, permet d’automatiser les audits
de sécurité de réseaux Wi-Fi (scan, capture de handshake, désauthentification, cracking, etc.).

⚠️ **Disclaimer / Avertissement Légal :**
-----------------------------------------
- Cet outil est destiné exclusivement à l’apprentissage et aux tests d’intrusion légaux.
- Toute utilisation non autorisée est strictement interdite et peut constituer une infraction
  pénale selon la législation en vigueur dans votre pays.
- L’auteur décline toute responsabilité en cas d’utilisation malveillante ou illégale de ce script.

Sommaire
--------
1. Description Générale
2. Fonctionnalités Clés
3. Dépendances (Python & Outils Externes)
4. Installation & Utilisation
5. Configuration Recommandée
6. Roadmap / Pistes d’Évolution
7. Licence

1. Description Générale
-----------------------
Ce projet vise à fournir une interface graphique (GUI) simple et intuitive pour lancer des
audits de sécurité Wi-Fi. Il s’appuie en grande partie sur la suite aircrack-ng et utilise
Python (Tkinter) pour gérer l’automatisation et l’affichage des résultats.

2. Fonctionnalités Clés
-----------------------
- Activation/Désactivation du mode moniteur
- Scan des réseaux à proximité
- Identification des stations connectées
- Désauthentification ciblée
- Capture de handshakes WPA/WPA2
- Attaque par dictionnaire (avec aircrack-ng)
- Interface graphique en Tkinter (progress bar, tableaux, logs, etc.)

3. Dépendances (Python & Outils Externes)
-----------------------------------------
**Python :**
- Version ≥ 3.6 (testé en 3.8+)
- Bibliothèques standards : tkinter, subprocess, threading, os (incluses de base)
- (Optionnel) Autres libs à préciser selon vos besoins (voir `requirements.txt`)

**Outils Externes :**
- aircrack-ng (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)
- iwconfig, ifconfig/ip, systemctl, NetworkManager, etc. (environnement Linux)
- Wordlists (ex. rockyou.txt)

4. Installation & Utilisation
-----------------------------
**Étapes de Base :**
1. Cloner le repo :
   ```bash
   git clone https://github.com/OwlHacker-source/Wi-Fi_Hacking_Tool.git
   cd wifi-hacking-tool
   
