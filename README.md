Description of the setup of a new raspberry:
- run a new image from raspberry pi image for pi5_64x

You got it. Here’s a clean, repeatable way to get setup_adsb_v1-2.sh onto a fresh Pi 5 and run it.

First install the file setup_adsb_vn-n.sh
On the computer open a new shell and paste:
scp setup_adsb_v1-2.sh pi@lsgs.local:/home/pi/
[make sure you are connected with only one pi]

⸻

A) Copy the script to the Pi (pick one)

Option 1 — From your Mac via hotspot/LAN (recommended)
	1.	Find the Pi’s IP (iPhone hotspot is usually 172.20.10.x; Android often 192.168.43.x).
	2.	From your Mac:

# adjust the source path if your script lives elsewhere
scp /Users/frederic/Downloads/setup_adsb_v1-2.sh lsgs@<pi-ip>:~

Option 2 — With keyboard/HDMI & USB drive
	•	Put setup_adsb_v1-2.sh on a USB stick.
	•	Plug into the Pi, then on the Pi:

cp /media/$USER/*/setup_adsb_v1-2.sh ~/

Option 3 — Before first boot (for next time)
	•	Mount the SD card’s boot partition on your Mac and drop the script there.
	•	After first boot on the Pi:

sudo cp /boot/setup_adsb_v1-2.sh ~/
sudo chown lsgs:lsgs ~/setup_adsb_v1-2.sh


⸻

B) Run the installer on the Pi
	1.	SSH into the Pi (or use the local terminal):

ssh lsgs@<pi-ip>

	2.	Make it executable and run with sudo:

chmod +x ~/setup_adsb_v1-2.sh
sudo /home/lsgs/setup_adsb_v1-2.sh

	3.	The script will prompt you for:

	•	Hostname, timezone
	•	Wi-Fi SSID/PSK (primary)
	•	Sixfab APN (super by default) and optional SIM PIN
	•	AWS: Access key, Secret key, Region (us-east-2), S3 prefix
	•	Optional: remote.it R3 registration code
	•	Optional: Tailscale auth key + tags
	•	Optional: your SSH public key (so key-based SSH works right away)

Let it run to completion. If it asks to install packages, say yes.

⸻

C) Reboot & verify

sudo reboot

After ~1–2 minutes, reconnect (hotspot/LAN or Tailscale/remote.it) and check:

# services
systemctl status dump1090-fa adsb-collector adsb-uploader --no-pager
systemctl status adsb-online-bootstrap.timer --no-pager

# network: Wi-Fi preferred; LTE fallback if Wi-Fi is absent
ip route | head -n 3
nmcli -p con show lte | egrep 'autoconnect|gsm\.apn|route-metric' || true

# uploader heartbeat + S3 flow
tail -n 40 ~/Documents/adsb/logs/uploader.log
aws s3 ls s3://adsbcsvdata/adsb_hex_data/Europe/switzerland/lsgs/ --region us-east-2 | tail

You should see:
	•	Active: active (running) for the three ADS-B services.
	•	Default route via wlan0 if Wi-Fi is present; wwan (lte) if not.
	•	“BOOTSTRAP tick” in uploader.log (hourly/boot watchdog).
	•	New .hex.gz arriving in S3.

⸻

Tips / gotchas
	•	If scp from the Mac says “No such file”, double-check the local path to the script.
	•	If SSH to <pi-ip> fails, try ssh lsgs@lsgs-01.local (mDNS may or may not work on hotspots).
	•	If you need to re-run the script later, just repeat:

sudo /home/lsgs/setup_adsb_v1-2.sh


	•	Keep your AWS keys, Wi-Fi SSID/PSK, Tailscale key, and remote.it code handy before you start; it makes the run smooth.

If you want, I can also give you a one-liner variant (Pi pulls the script with curl and runs it), to avoid using scp at all.
